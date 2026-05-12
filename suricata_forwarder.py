#!/usr/bin/env python3
"""
Suricata Log Forwarder
Chạy trên Linux server – đọc eve.json real-time và gửi event lên SOC server (Windows/Flask).

Usage:
  SOC_SERVER_URL=http://172.25.0.10:5000 python3 suricata_forwarder.py --log /var/log/suricata/eve.json
  hoặc: python3 suricata_forwarder.py --url http://172.25.0.10:5000 --log /var/log/suricata/eve.json
"""

import hashlib
import os
import re
import sys
import json
import time
import logging
import argparse
import requests
import socket
from collections import deque
from pathlib import Path
from datetime import datetime, timedelta, timezone
import threading
from typing import Any, Dict, Set

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        # Note: /var/log may require sudo. Adjust via env if needed.
        logging.FileHandler(os.environ.get("FORWARDER_LOG_PATH", "/var/log/suricata/forwarder.log"), encoding="utf-8"),
    ],
)
logger = logging.getLogger("SuricataForwarder")

DEFAULT_EVE_LOG = "/var/log/suricata/eve.json"
DEFAULT_SOC_URL = os.environ.get("SOC_SERVER_URL", "http://172.25.0.10:5000")
SOC_INGEST_TOKEN = os.environ.get("SOC_INGEST_TOKEN", "")
RETRY_ATTEMPTS = 3
RETRY_DELAY = 2
POLL_INTERVAL = 0.1
REQUEST_TIMEOUT = int(os.environ.get("SOC_REQUEST_TIMEOUT", "45"))


def _alert_dedupe_window_sec() -> float:
    """0 = tắt dedupe. Suricata đôi khi ghi 2 dòng alert gần giống nhau → chỉ gửi SOC/Telegram một lần trong cửa sổ này."""
    try:
        v = float(os.environ.get("SURICATA_ALERT_DEDUPE_SEC", "5") or "5")
    except Exception:
        v = 5.0
    return max(0.0, v)


_ALERT_DEDUPE_LOCK = threading.Lock()
_ALERT_DEDUPE_LAST: Dict[str, float] = {}


def _norm_port(v: Any) -> str:
    if v is None:
        return "-"
    try:
        return str(int(v))
    except (TypeError, ValueError):
        s = str(v).strip()
        return s if s else "-"


def _alert_fingerprint(log_entry: dict) -> str:
    """
    Khóa dedupe ổn định cho burst Suricata: hai dòng eve thường cách ~1s nhưng timestamp khác giây,
    hoặc một dòng có flow_id / pcap_cnt và dòng kia không — không dùng timestamp/pcap trong key,
    chỉ dựa vào SURICATA_ALERT_DEDUPE_SEC (monotonic) để giới hạn thời gian gom trùng.
    """
    a = log_entry.get("alert") if isinstance(log_entry.get("alert"), dict) else {}
    gid = int(a.get("gid") or 0)
    sig_id = int(a.get("signature_id") or 0)
    src = str(log_entry.get("src_ip") or "").strip().lower()
    dst = str(log_entry.get("dest_ip") or "").strip().lower()
    sp = _norm_port(log_entry.get("src_port"))
    dp = _norm_port(log_entry.get("dest_port"))
    pr = str(log_entry.get("proto") or "").strip().lower()
    return f"v3|{src}|{dst}|{sp}|{dp}|{pr}|{gid}|{sig_id}"


def _alert_dedupe_should_skip(log_entry: dict) -> bool:
    """True nếu alert trùng fingerprint với bản vừa gửi SOC thành công trong cửa sổ dedupe."""
    w = _alert_dedupe_window_sec()
    if w <= 0:
        return False
    key = _alert_fingerprint(log_entry)
    now = time.monotonic()
    with _ALERT_DEDUPE_LOCK:
        for k, t in list(_ALERT_DEDUPE_LAST.items()):
            if (now - t) > w * 8:
                del _ALERT_DEDUPE_LAST[k]
        last = _ALERT_DEDUPE_LAST.get(key)
        return last is not None and (now - last) < w


def _alert_dedupe_on_soc_success(log_entry: dict) -> None:
    """Gọi sau khi POST /log trả HTTP 200 cho event alert (tránh dedupe trước khi gửi thành công)."""
    if log_entry.get("event_type") != "alert":
        return
    w = _alert_dedupe_window_sec()
    if w <= 0:
        return
    key = _alert_fingerprint(log_entry)
    with _ALERT_DEDUPE_LOCK:
        _ALERT_DEDUPE_LAST[key] = time.monotonic()


_VN_TZ = timezone(timedelta(hours=7))


def _normalize_suricata_ts_for_parse(s: str) -> str:
    """Suricata eve dùng +0000 không có ':' — fromisoformat (Python 3.10) cần +00:00."""
    t = (s or "").strip().replace("Z", "+00:00")
    if re.search(r"[+-]\d{4}$", t) and not re.search(r"[+-]\d{2}:\d{2}$", t):
        t = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", t)
    return t


def _eve_ts_display_utc7(raw: str) -> str:
    """Timestamp eve.json → giờ Việt Nam UTC+7 (Telegram)."""
    s = (raw or "").strip()
    if not s:
        return "—"
    try:
        t = _normalize_suricata_ts_for_parse(s)
        dt = datetime.fromisoformat(t)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(_VN_TZ).strftime("%Y-%m-%d %H:%M:%S") + " (UTC+7)"
    except Exception:
        return s


_TG_BURST_LOCK = threading.Lock()
_TG_BURST_LAST: Dict[str, float] = {}


def _telegram_burst_window_sec() -> float:
    try:
        return max(0.0, float(os.environ.get("TELEGRAM_IDS_BURST_SEC", "20") or "20"))
    except Exception:
        return 20.0


def _telegram_burst_key(log_entry: dict) -> str:
    src = str(log_entry.get("src_ip") or "").strip().lower()
    dst = str(log_entry.get("dest_ip") or "").strip().lower()
    return f"tg|{src}|{dst}"


def _telegram_burst_should_skip(log_entry: dict) -> bool:
    """Một tin Telegram / cặp src→dst trong TELEGRAM_IDS_BURST_SEC (mặc định 20s) — nhiều rule cùng lúc chỉ 1 tin."""
    w = _telegram_burst_window_sec()
    if w <= 0:
        return False
    key = _telegram_burst_key(log_entry)
    if key == "tg||":
        return False
    now = time.monotonic()
    with _TG_BURST_LOCK:
        for k, t in list(_TG_BURST_LAST.items()):
            if (now - t) > w * 6:
                del _TG_BURST_LAST[k]
        last = _TG_BURST_LAST.get(key)
        return last is not None and (now - last) < w


def _telegram_burst_mark_sent(log_entry: dict) -> None:
    w = _telegram_burst_window_sec()
    if w <= 0:
        return
    key = _telegram_burst_key(log_entry)
    if key == "tg||":
        return
    with _TG_BURST_LOCK:
        _TG_BURST_LAST[key] = time.monotonic()


# ─────────────────────────────────────────────
# Debug instrumentation (NDJSON)
# ─────────────────────────────────────────────
# #region agent log
_DEBUG_LOG_PATH = Path(__file__).resolve().parent / "debug-44bc52.log"
_DEBUG_SESSION_ID = "44bc52"
_DEBUG_LOCK = threading.Lock()
_DEBUG_LOGGED_TYPES: Set[str] = set()


def _debug_log(*, runId: str, hypothesisId: str, location: str, message: str, data: dict) -> None:
    payload = {
        "sessionId": _DEBUG_SESSION_ID,
        "runId": runId,
        "hypothesisId": hypothesisId,
        "location": location,
        "message": message,
        "data": data,
        "timestamp": int(datetime.now().timestamp() * 1000),
    }
    try:
        with _DEBUG_LOCK:
            _DEBUG_LOG_PATH.open("a", encoding="utf-8").write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        pass


# #endregion agent log


DEFAULT_FORWARD_EVENT_TYPES = "alert,flow,http,tls,dns,fileinfo,stats"
FORWARD_EVENT_TYPES = set(
    [x.strip() for x in os.environ.get("FORWARD_EVENT_TYPES", DEFAULT_FORWARD_EVENT_TYPES).split(",") if x.strip()]
)

# Telegram: biến môi trường TELEGRAM_* (nếu có) được ưu tiên; không có thì dùng giá trị mặc định bên dưới.
# Cảnh báo: token trong source có thể lộ qua git/copy — nên dùng env trên production và đổi token nếu đã lộ.
_TELEGRAM_DEFAULT_BOT_TOKEN = "8784905578:AAENtI143ed3qPMsaQverjfPIyXsjxYSNb4"
_TELEGRAM_DEFAULT_CHAT_ID = "6929846070"
TELEGRAM_BOT_TOKEN = (os.environ.get("TELEGRAM_BOT_TOKEN") or _TELEGRAM_DEFAULT_BOT_TOKEN).strip()
TELEGRAM_CHAT_ID = (os.environ.get("TELEGRAM_CHAT_ID") or _TELEGRAM_DEFAULT_CHAT_ID).strip()
_IDS_ALERT_TG_HINT_SHOWN = False


_TG_BODY_LOCK = threading.Lock()
_TG_LAST_BODY_HASH = ""
_TG_LAST_BODY_MONO = 0.0


def _telegram_message_dedupe_sec() -> float:
    try:
        return max(0.0, float(os.environ.get("TELEGRAM_MESSAGE_DEDUPE_SEC", "45") or "45"))
    except Exception:
        return 45.0


def _telegram_send(text: str) -> bool:
    global _TG_LAST_BODY_HASH, _TG_LAST_BODY_MONO
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        # #region agent log
        _debug_log(
            runId="pre",
            hypothesisId="H6_TG_SEND",
            location="suricata_forwarder.py:_telegram_send",
            message="Telegram not configured (missing env)",
            data={"has_token": bool(TELEGRAM_BOT_TOKEN), "has_chat_id": bool(TELEGRAM_CHAT_ID)},
        )
        # #endregion agent log
        return False
    w = _telegram_message_dedupe_sec()
    body_hash = ""
    if w > 0:
        body_hash = hashlib.sha256((text or "").encode("utf-8", errors="replace")).hexdigest()
        now = time.monotonic()
        with _TG_BODY_LOCK:
            if body_hash == _TG_LAST_BODY_HASH and (now - _TG_LAST_BODY_MONO) < w:
                logger.info("⏭️  Bỏ qua Telegram trùng nội dung (%.0fs) — không gọi API lần 2/3", w)
                return True
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        r = requests.post(
            url,
            json={"chat_id": TELEGRAM_CHAT_ID, "text": text, "disable_web_page_preview": True},
            timeout=35,
        )
        # #region agent log
        _debug_log(
            runId="pre",
            hypothesisId="H6_TG_SEND",
            location="suricata_forwarder.py:_telegram_send",
            message="Telegram send attempted",
            data={"http_status": int(getattr(r, "status_code", 0) or 0), "ok": bool(getattr(r, "ok", False))},
        )
        # #endregion agent log
        if r.status_code == 200 and w > 0 and body_hash:
            with _TG_BODY_LOCK:
                _TG_LAST_BODY_HASH = body_hash
                _TG_LAST_BODY_MONO = time.monotonic()
        return r.status_code == 200
    except Exception as e:
        # #region agent log
        _debug_log(
            runId="pre",
            hypothesisId="H6_TG_SEND",
            location="suricata_forwarder.py:_telegram_send",
            message="Telegram send failed (exception)",
            data={"errorType": type(e).__name__, "error": str(e)[:220]},
        )
        # #endregion agent log
        return False


def send_log_to_soc(log_entry: dict, soc_url: str) -> bool:
    global _IDS_ALERT_TG_HINT_SHOWN
    if log_entry.get("event_type") == "alert" and _alert_dedupe_should_skip(log_entry):
        dw = _alert_dedupe_window_sec()
        logger.info("⏭️  Bỏ qua alert trùng (dedupe %.0fs) — cùng flow/signature trong cửa sổ ngắn", dw)
        return True
    endpoint = f"{soc_url.rstrip('/')}/log"
    for attempt in range(1, RETRY_ATTEMPTS + 1):
        try:
            response = requests.post(
                endpoint,
                json=log_entry,
                headers={
                    "Content-Type": "application/json",
                    **({"X-SOC-Token": SOC_INGEST_TOKEN} if SOC_INGEST_TOKEN else {}),
                },
                timeout=REQUEST_TIMEOUT,
            )

            if response.status_code == 200:
                result = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
                status = result.get("status", "unknown")
                if status == "processed" and log_entry.get("event_type") == "alert":
                    # #region agent log
                    _debug_log(
                        runId="pre",
                        hypothesisId="H3_IDS_UNKNOWN",
                        location="suricata_forwarder.py:send_log_to_soc",
                        message="SOC processed alert response",
                        data={
                            "attack_type": result.get("attack_type"),
                            "severity": result.get("severity"),
                            "recommended_action": result.get("recommended_action"),
                        },
                    )
                    # #endregion agent log
                    logger.info(
                        "✅ Alert gửi thành công | %s -> %s | %s | Severity: %s",
                        log_entry.get("src_ip", "?"),
                        log_entry.get("dest_ip", "?"),
                        result.get("attack_type", "?"),
                        result.get("severity", "?"),
                    )
                    # Optional: Telegram for IDS alerts (only summary; no secrets)
                    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
                        if _telegram_burst_should_skip(log_entry):
                            logger.info(
                                "⏭️  Bỏ qua Telegram burst (cùng src→dst trong %.0fs) — chỉ gửi một tin / đợt tấn công",
                                _telegram_burst_window_sec(),
                            )
                        else:

                            def sev_emoji(s: str) -> str:
                                x = (s or "").strip().lower()
                                if x == "critical":
                                    return "🔴"
                                if x == "high":
                                    return "🟠"
                                if x == "medium":
                                    return "🟡"
                                if x == "low":
                                    return "🟢"
                                return "🟡"

                            def action_emoji(a: str) -> str:
                                x = (a or "").strip().lower()
                                if "block" in x:
                                    return "🚫"
                                if "isolate" in x or "contain" in x:
                                    return "🛑"
                                if "mitigate" in x or "ddos" in x:
                                    return "🛡️"
                                if "monitor" in x:
                                    return "👁️"
                                return "🔎"

                            a = log_entry.get("alert") or {}
                            src_ip = log_entry.get("src_ip") or "?"
                            dst_ip = log_entry.get("dest_ip") or "?"
                            src_p = log_entry.get("src_port")
                            dst_p = log_entry.get("dest_port")
                            proto = (log_entry.get("proto") or "").upper() or "—"
                            signature = (a.get("signature") or "").strip() or "—"
                            category = (a.get("category") or "").strip() or "—"
                            attack_type = (result.get("attack_type") or "Unknown").strip()
                            severity = (result.get("severity") or "Medium").strip()
                            rec_action = (result.get("recommended_action") or "INVESTIGATE").strip()
                            confidence = "Medium"

                            src = f"{src_ip}:{src_p}" if src_p else f"{src_ip}"
                            dst = f"{dst_ip}:{dst_p}" if dst_p else f"{dst_ip}"

                            ts = _eve_ts_display_utc7(str(log_entry.get("timestamp") or ""))

                            analysis = (
                                f"Hệ thống phát hiện cảnh báo từ IDS (Suricata): {signature}. "
                                f"Khuyến nghị xử lý theo playbook SOC cho loại tấn công tương ứng."
                            )
                            mitigations = [
                                "1. ⚡ Kiểm tra access log/web log tại thời điểm cảnh báo, xác định request cụ thể và payload.",
                                "2. ⚡ Chặn nguồn tấn công ở WAF/Firewall nếu là IP bất thường hoặc có dấu hiệu lặp lại.",
                                "3. Cập nhật rule/WAF và vá lỗ hổng ứng dụng (input validation, allowlist, encoding).",
                            ]

                            msg = (
                                "🚨 CẢNH BÁO BẢO MẬT - SOC ALERT 🚨\n"
                                "━━━━━━━━━━━━━━━━━━━━━━━━\n"
                                f"📅 Thời gian: {ts}\n"
                                "━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
                                "⚔️ THÔNG TIN TẤN CÔNG\n"
                                f"• Loại tấn công: {attack_type}\n"
                                f"• Chữ ký IDS: {signature}\n"
                                f"• Danh mục: {category}\n\n"
                                "🌐 THÔNG TIN MẠNG\n"
                                f"• Nguồn: {src}\n"
                                f"• Đích: {dst}\n"
                                f"• Giao thức: {proto}\n\n"
                                "📊 ĐÁNH GIÁ AI\n"
                                f"• Mức độ: {sev_emoji(severity)} {severity}\n"
                                f"• Độ chắc chắn: {confidence}\n"
                                f"• Hành động: {action_emoji(rec_action)} {rec_action}\n\n"
                                "📝 PHÂN TÍCH\n"
                                f"{analysis}\n\n"
                                "🛡️ BIỆN PHÁP XỬ LÝ\n"
                                "   " + "\n   ".join(mitigations) + "\n\n"
                                "━━━━━━━━━━━━━━━━━━━━━━━━\n"
                                "🤖 Powered by SOC-AI System\n"
                            )
                            # #region agent log
                            _debug_log(
                                runId="pre",
                                hypothesisId="H6_TG_SEND",
                                location="suricata_forwarder.py:send_log_to_soc",
                                message="Telegram message formatted",
                                data={"len": len(msg), "severity": severity, "attack_type": attack_type},
                            )
                            # #endregion agent log
                            if _telegram_send(msg):
                                _telegram_burst_mark_sent(log_entry)
                    elif not _IDS_ALERT_TG_HINT_SHOWN:
                        _IDS_ALERT_TG_HINT_SHOWN = True
                        logger.info(
                            "Telegram không gửi từ forwarder (thiếu TELEGRAM_* trên máy này). "
                            "Đặt TELEGRAM_BOT_TOKEN và TELEGRAM_CHAT_ID trên máy chạy SOC (Flask) để nhận tin khi có alert Suricata."
                        )
                    _alert_dedupe_on_soc_success(log_entry)
                return True

            if response.status_code == 403:
                logger.error("❌ Forbidden (token mismatch?) from SOC server: %s", endpoint)
                return False

            if response.status_code == 500:
                logger.warning("⚠️  SOC server trả về 500 – lần %d/%d", attempt, RETRY_ATTEMPTS)
            else:
                logger.error("❌ HTTP %d từ SOC server: %s", response.status_code, (response.text or "")[:200])

        except requests.exceptions.ConnectionError:
            logger.error("❌ Không thể kết nối đến SOC server %s – lần %d/%d", endpoint, attempt, RETRY_ATTEMPTS)
        except requests.exceptions.Timeout:
            logger.error("❌ Timeout kết nối SOC server – lần %d/%d", attempt, RETRY_ATTEMPTS)
        except Exception as e:
            logger.error("❌ Lỗi không mong đợi: %s – lần %d/%d", e, attempt, RETRY_ATTEMPTS)

        if attempt < RETRY_ATTEMPTS:
            time.sleep(RETRY_DELAY)

    logger.error("💀 Gửi thất bại sau %d lần thử. Bỏ qua event này.", RETRY_ATTEMPTS)
    return False


def is_interesting_event(log_entry: dict) -> bool:
    if not isinstance(log_entry, dict):
        return False
    event_type = log_entry.get("event_type")
    if not event_type or event_type not in FORWARD_EVENT_TYPES:
        return False
    if event_type == "alert" and "alert" not in log_entry:
        return False
    return True


def tail_eve_log(log_path: str, soc_url: str, *, from_beginning: bool = False, backfill_lines: int = 0):
    logger.info("🔍 Bắt đầu theo dõi: %s", log_path)
    logger.info("📡 SOC Server: %s", soc_url)

    stats = {
        "total_lines": 0,
        "events_sent": 0,
        "events_skipped": 0,
        "events_failed": 0,
        "start_time": datetime.now(),
    }

    try:
        health_url = f"{soc_url.rstrip('/')}/health"
        # #region agent log
        host = ""
        try:
            host = str(requests.utils.urlparse(soc_url).hostname or "")
        except Exception:
            host = ""
        resolved = None
        try:
            resolved = socket.gethostbyname(host) if host else None
        except Exception:
            resolved = None
        _debug_log(
            runId="pre",
            hypothesisId="H1_SOC_URL_CONNECT",
            location="suricata_forwarder.py:tail_eve_log",
            message="SOC health check starting",
            data={"soc_url": soc_url, "health_url": health_url, "host": host, "resolved": resolved},
        )
        # #endregion agent log
        r = requests.get(health_url, timeout=5)
        if r.status_code == 200:
            logger.info("✅ SOC Server đang hoạt động: %s", r.json())
        else:
            logger.warning("⚠️  SOC Server health check thất bại: %d", r.status_code)
    except Exception as e:
        # #region agent log
        _debug_log(
            runId="pre",
            hypothesisId="H1_SOC_URL_CONNECT",
            location="suricata_forwarder.py:tail_eve_log",
            message="SOC health check failed",
            data={"errorType": type(e).__name__, "error": str(e)[:260]},
        )
        # #endregion agent log
        logger.warning("⚠️  Không thể kiểm tra SOC Server health: %s", e)

    try:
        file = open(log_path, "r", encoding="utf-8", errors="replace")
        # Default behavior: tail -f (start at EOF).
        # If from_beginning/backfill requested, we replay older lines for testing/backfill.
        if from_beginning:
            file.seek(0, 0)
        elif backfill_lines and backfill_lines > 0:
            file.seek(0, 0)
        else:
            file.seek(0, 2)
        current_inode = os.fstat(file.fileno()).st_ino
        logger.info("📂 Đã mở file, đang chờ log mới...")
        # #region agent log
        _debug_log(
            runId="pre",
            hypothesisId="H7_TAIL_MODE",
            location="suricata_forwarder.py:tail_eve_log",
            message="Tail mode selected",
            data={"from_beginning": bool(from_beginning), "backfill_lines": int(backfill_lines or 0)},
        )
        # #endregion agent log
    except FileNotFoundError:
        logger.error("❌ Không tìm thấy file: %s", log_path)
        logger.error("   Kiểm tra Suricata có đang chạy không: systemctl status suricata")
        sys.exit(1)
    except PermissionError:
        logger.error("❌ Không có quyền đọc file: %s", log_path)
        logger.error("   Thử chạy với sudo hoặc thêm user vào group suricata")
        sys.exit(1)

    logger.info("👁️  Đang theo dõi log... (Ctrl+C để dừng)")
    try:
        # Optional backfill: process last N lines before switching to tail mode.
        if (not from_beginning) and backfill_lines and backfill_lines > 0:
            # Read full file once; keep only last N lines to avoid huge memory.
            buf = deque(maxlen=int(backfill_lines))
            for ln in file:
                buf.append(ln)
            for ln in buf:
                stats["total_lines"] += 1
                line = (ln or "").strip()
                if not line:
                    continue
                try:
                    log_entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not is_interesting_event(log_entry):
                    stats["events_skipped"] += 1
                    continue
                success = send_log_to_soc(log_entry, soc_url)
                if success:
                    stats["events_sent"] += 1
                else:
                    stats["events_failed"] += 1
            # After backfill, jump to EOF to continue tailing.
            file.seek(0, 2)

        last_read_ts = time.monotonic()
        last_idle_log_ts = 0.0
        while True:
            line = file.readline()
            if not line:
                now = time.monotonic()
                # #region agent log
                if (now - last_read_ts) > 10.0 and (now - last_idle_log_ts) > 10.0:
                    last_idle_log_ts = now
                    try:
                        pos = int(file.tell())
                    except Exception:
                        pos = -1
                    _debug_log(
                        runId="pre",
                        hypothesisId="H8_TAIL_IDLE",
                        location="suricata_forwarder.py:tail_loop",
                        message="No new lines observed (idle)",
                        data={"pos": pos, "inode": int(current_inode), "log_path": log_path},
                    )
                # #endregion agent log
                try:
                    new_inode = os.stat(log_path).st_ino
                    if new_inode != current_inode:
                        logger.info("🔄 Phát hiện file rotation, mở lại file...")
                        file.close()
                        file = open(log_path, "r", encoding="utf-8", errors="replace")
                        current_inode = new_inode
                        continue
                except FileNotFoundError:
                    pass

                time.sleep(POLL_INTERVAL)
                continue

            stats["total_lines"] += 1
            last_read_ts = time.monotonic()
            line = line.strip()
            if not line:
                continue

            try:
                log_entry = json.loads(line)
            except json.JSONDecodeError:
                logger.debug("Không parse được dòng JSON: %s", line[:100])
                continue

            if not is_interesting_event(log_entry):
                stats["events_skipped"] += 1
                continue

            event_type = log_entry.get("event_type")
            if event_type in ("flow", "alert") and event_type not in _DEBUG_LOGGED_TYPES:
                _DEBUG_LOGGED_TYPES.add(event_type)
                # #region agent log
                _debug_log(
                    runId="pre",
                    hypothesisId="A",
                    location="suricata_forwarder.py:forward_event",
                    message="Forwarding event type (one-time sample)",
                    data={
                        "event_type": event_type,
                        "has_flow": bool(log_entry.get("flow")),
                        "has_alert": bool(log_entry.get("alert")),
                    },
                )
                # #endregion agent log

            success = send_log_to_soc(log_entry, soc_url)
            if success:
                stats["events_sent"] += 1
            else:
                stats["events_failed"] += 1

            if stats["total_lines"] % 200 == 0:
                elapsed = (datetime.now() - stats["start_time"]).seconds
                logger.info(
                    "📊 Thống kê: %d dòng đọc | %d events gửi | %d thất bại | %ds uptime",
                    stats["total_lines"],
                    stats["events_sent"],
                    stats["events_failed"],
                    elapsed,
                )
    except KeyboardInterrupt:
        logger.info("\n👋 Nhận Ctrl+C, đang dừng forwarder...")
    finally:
        file.close()
        elapsed = (datetime.now() - stats["start_time"]).total_seconds()
        logger.info(
            "📊 Thống kê cuối: %d dòng | %d events gửi | %d thất bại | %.1fs runtime",
            stats["total_lines"],
            stats["events_sent"],
            stats["events_failed"],
            elapsed,
        )


def parse_args():
    parser = argparse.ArgumentParser(description="Suricata Eve.json Log Forwarder → SOC Server")
    parser.add_argument("--url", default=DEFAULT_SOC_URL, help=f"URL SOC server (mặc định: {DEFAULT_SOC_URL})")
    parser.add_argument("--log", default=DEFAULT_EVE_LOG, help=f"Đường dẫn eve.json (mặc định: {DEFAULT_EVE_LOG})")
    parser.add_argument(
        "--from-beginning",
        action="store_true",
        help="Đọc từ đầu file (replay) thay vì tail từ cuối (dùng để test/backfill).",
    )
    parser.add_argument(
        "--backfill-lines",
        type=int,
        default=0,
        help="Replay N dòng cuối của eve.json trước khi tail realtime (0 = tắt).",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    tail_eve_log(args.log, args.url, from_beginning=bool(args.from_beginning), backfill_lines=int(args.backfill_lines or 0))

