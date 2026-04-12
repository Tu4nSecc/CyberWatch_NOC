import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, Response, jsonify, request, stream_with_context

from lynis_service import iter_sse_lynis_scan

from llm_router import route_llm
from ml_model import explain_zabbix_alert
from soc_db import SocAnalyticsDB, VN_TZ
from zabbix_client import ZabbixClient, ZabbixConfig


app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s - %(message)s")
logger = logging.getLogger("SOCZabbixServer")


@app.after_request
def _no_cache_json_api(response: Any) -> Any:
    """Avoid stale dashboard JSON when browser caches GET /api/* (fixes refresh without F5)."""
    p = request.path or ""
    if p.startswith("/api/") or p in ("/kpis", "/history", "/alerts", "/top-rules", "/metrics"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response


DB_PATH = os.environ.get("SOC_ANALYTICS_DB_PATH", "soc_analytics.db")
POLL_INTERVAL_SEC = int(os.environ.get("ZABBIX_POLL_INTERVAL_SEC", "30"))
ZABBIX_URL = os.environ.get("ZABBIX_API_URL", "http://172.25.0.20/zabbix/api_jsonrpc.php")
ZABBIX_USER = os.environ.get("ZABBIX_USERNAME", "Admin")
ZABBIX_PASSWORD = os.environ.get("ZABBIX_PASSWORD", "zabbix")
ZABBIX_HOST_NAME = os.environ.get("ZABBIX_HOST_NAME", "Linux Server")
SOC_CHAT_MODE = os.environ.get("SOC_CHAT_MODE", "local")
LYNIS_REMOTE_ENABLED = os.environ.get("LYNIS_REMOTE_ENABLED", "1").strip().lower() in ("1", "true", "yes")
SOC_INGEST_TOKEN = os.environ.get("SOC_INGEST_TOKEN", "")

DEBUG_LOG_PATH = Path(__file__).resolve().parent / "debug-9cf80c.log"
DEBUG_LOCK = threading.Lock()
AGENT_DEBUG_LOG_PATH = Path(__file__).resolve().parent / "debug-f300aa.log"
AGENT_DEBUG_LOCK = threading.Lock()

 # #region agent log
DEBUG44_LOG_PATH = Path(__file__).resolve().parent / "debug-44bc52.log"
DEBUG44_LOCK = threading.Lock()


def _debug44_log(*, run_id: str, hypothesis_id: str, location: str, message: str, data: Dict[str, Any]) -> None:
    """Debug-mode evidence log (session 44bc52). Do not log secrets."""
    payload = {
        "sessionId": "44bc52",
        "runId": run_id,
        "hypothesisId": hypothesis_id,
        "location": location,
        "message": message,
        "data": data,
        "timestamp": int(time.time() * 1000),
    }
    try:
        with DEBUG44_LOCK:
            DEBUG44_LOG_PATH.open("a", encoding="utf-8").write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        pass


# #endregion agent log


# #region debug89 agent log
DEBUG89_LOG_PATH = Path(__file__).resolve().parent / "debug-89ebba.log"


def _debug89_log(*, run_id: str, hypothesis_id: str, location: str, message: str, data: Dict[str, Any]) -> None:
    payload = {
        "sessionId": "89ebba",
        "runId": run_id,
        "hypothesisId": hypothesis_id,
        "location": location,
        "message": message,
        "data": data,
        "timestamp": int(time.time() * 1000),
    }
    try:
        DEBUG89_LOG_PATH.open("a", encoding="utf-8").write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        pass


# #endregion debug89 agent log

ZABBIX_ITEM_KEYS: List[str] = [
    "system.cpu.util",
    "system.cpu.load[all,avg1]",
    "system.cpu.load[all,avg5]",
    "system.cpu.load[all,avg15]",
    "system.cpu.switches",
    "vm.memory.utilization",
    "vm.memory.size[available]",
    "vm.memory.size[cached]",
    "vm.memory.size[buffers]",
    "system.swap.size[,pfree]",
    "vfs.fs.size[/,pused]",
    "vfs.fs.inode[/,pfree]",
    'net.if.in["zttqhuceey"]',
    'net.if.out["zttqhuceey"]',
    "system.uptime",
    "system.users.num",
    "system.sw.os",
    "proc.num",
    "proc.num[,,run]",
    "vfs.dev.read.await[sda]",
    "vfs.dev.write.await[sda]",
    "system.hostname",
    "vfs.file.cksum[/etc/passwd,sha256]",
]


def _debug_log(*, run_id: str, hypothesis_id: str, location: str, message: str, data: Dict[str, Any]) -> None:
    payload = {
        "sessionId": "9cf80c",
        "runId": run_id,
        "hypothesisId": hypothesis_id,
        "location": location,
        "message": message,
        "data": data,
        "timestamp": int(time.time() * 1000),
    }
    try:
        with DEBUG_LOCK:
            DEBUG_LOG_PATH.open("a", encoding="utf-8").write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _agent_log(*, run_id: str, hypothesis_id: str, location: str, message: str, data: Dict[str, Any]) -> None:
    """
    Debug-mode evidence log (session f300aa). Do not log secrets.
    """
    payload = {
        "sessionId": "f300aa",
        "runId": run_id,
        "hypothesisId": hypothesis_id,
        "location": location,
        "message": message,
        "data": data,
        "timestamp": int(time.time() * 1000),
    }
    try:
        with AGENT_DEBUG_LOCK:
            AGENT_DEBUG_LOG_PATH.open("a", encoding="utf-8").write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _ids_severity_label(raw: Any) -> str:
    """
    Suricata severity is commonly 1 (high) .. 3 (low). We normalize to Critical/High/Medium/Low.
    Accepts numeric or text and returns one of: Critical|High|Medium|Low.
    """
    try:
        n = int(raw)
        if n <= 1:
            return "Critical"
        if n == 2:
            return "High"
        if n == 3:
            return "Medium"
        return "Low"
    except Exception:
        s = str(raw or "").strip().lower()
        if s in ("critical", "crit"):
            return "Critical"
        if s in ("high",):
            return "High"
        if s in ("medium", "med"):
            return "Medium"
        if s in ("low", "info", "informational"):
            return "Low"
        return "Medium"


def _ids_quick_ai(alert_log: Dict[str, Any]) -> Dict[str, Any]:
    """
    Lightweight rule-based enrichment for IDS alerts to power the dashboard and /log response.
    Avoid secrets and keep deterministic.
    """
    sig = str(((alert_log.get("alert") or {}).get("signature") or "")).lower()
    cat = str(((alert_log.get("alert") or {}).get("category") or "")).lower()
    sev = _ids_severity_label(((alert_log.get("alert") or {}).get("severity") or alert_log.get("severity")))

    def has_any(s: str, needles: Tuple[str, ...]) -> bool:
        return any(n in (s or "") for n in needles)

    attack_type = "Unknown"
    if has_any(sig, ("path traversal", "directory traversal", "traversal")) or has_any(
        cat, ("path traversal", "directory traversal", "traversal")
    ):
        attack_type = "Path Traversal"
    elif has_any(sig, ("lfi", "local file inclusion", "file inclusion")) or has_any(cat, ("lfi", "file inclusion")):
        attack_type = "File Inclusion (LFI/RFI)"
    elif has_any(sig, ("sql", "sqli")) or has_any(cat, ("sql", "sqli")):
        attack_type = "SQL Injection"
    elif has_any(sig, ("xss", "cross site", "cross-site")) or has_any(cat, ("xss",)):
        attack_type = "XSS"
    elif has_any(sig, ("rce", "remote code", "code execution", "command injection")) or has_any(cat, ("rce",)):
        attack_type = "Remote Code Execution"
    elif has_any(sig, ("brute", "password", "login")) or has_any(cat, ("bruteforce", "brute")):
        attack_type = "Brute Force"
    elif has_any(sig, ("scan", "nmap", "recon", "portscan", "port scan")) or has_any(cat, ("recon", "scan")):
        attack_type = "Scanning / Recon"
    elif has_any(sig, ("ddos", "dos", "syn flood", "udp flood", "icmp flood")) or has_any(
        cat, ("attempted-dos", "dos", "ddos", "denial")
    ):
        attack_type = "DoS / DDoS"
    elif has_any(sig, ("c2", "command and control", "botnet", "beacon")) or has_any(cat, ("c2", "botnet")):
        attack_type = "C2 / Botnet"
    elif has_any(sig, ("malware", "trojan", "worm", "ransom")) or has_any(cat, ("malware", "trojan")):
        attack_type = "Malware"

    # Action should diversify by both type and severity.
    recommended_action = "INVESTIGATE"
    if attack_type in ("SQL Injection", "XSS", "Remote Code Execution", "Malware", "C2 / Botnet"):
        recommended_action = "ISOLATE + BLOCK + PATCH"
    elif attack_type in ("Brute Force", "Scanning / Recon"):
        recommended_action = "RATE-LIMIT + BLOCK"
    elif attack_type == "DoS / DDoS":
        recommended_action = "MITIGATE DDoS + RATE-LIMIT"
    else:
        if sev in ("Critical", "High"):
            recommended_action = "CONTAIN + INVESTIGATE"
        elif sev == "Medium":
            recommended_action = "INVESTIGATE"
        else:
            recommended_action = "MONITOR"

    # #region agent log
    _debug44_log(
        run_id="pre",
        hypothesis_id="H3_IDS_UNKNOWN",
        location="soc_server.py:_ids_quick_ai",
        message="IDS classification result",
        data={
            "sig_preview": (sig[:80] if sig else ""),
            "cat": cat,
            "attack_type": attack_type,
            "severity": sev,
            "recommended_action": recommended_action,
        },
    )
    # #endregion agent log

    return {
        "attack_type": attack_type,
        "confidence": "Medium",
        "recommended_action": recommended_action,
        "severity": sev,
    }


def _ssh_sha256_files(*, target_ip: str, user: str, ssh_pass: str, sudo_pass: str, port: int, files: List[str]) -> Dict[str, Any]:
    """
    Compute SHA256 on the Linux target via SSH + sudo sha256sum.
    Returns: {file: {checksum: str|None, status: 'VERIFIED'|'UNKNOWN', error: str|None}}
    """
    try:
        import paramiko
    except ImportError:
        return {f: {"checksum": None, "status": "UNKNOWN", "error": "paramiko missing"} for f in files}

    out: Dict[str, Any] = {}
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        import shlex

        client.connect(
            hostname=target_ip,
            port=port,
            username=user,
            password=ssh_pass,
            timeout=30,
            banner_timeout=30,
            auth_timeout=30,
        )
        for f in files:
            f2 = (f or "").strip()
            if not f2:
                continue
            # sudo -S with password; sha256sum prints: "<hash>  <file>"
            sp = shlex.quote(sudo_pass)
            fp = shlex.quote(f2)
            cmd = f"echo {sp} | sudo -S -p '' sha256sum {fp} 2>/dev/null || true"
            _stdin, stdout, _stderr = client.exec_command(cmd, get_pty=True, timeout=25)
            text = stdout.read().decode("utf-8", errors="replace").strip()
            checksum = None
            if text:
                parts = text.split()
                if parts and len(parts[0]) >= 64:
                    checksum = parts[0]
            out[f2] = {"checksum": checksum, "status": ("VERIFIED" if checksum else "UNKNOWN"), "error": None}
    except Exception as exc:
        for f in files:
            out[(f or "").strip()] = {"checksum": None, "status": "UNKNOWN", "error": str(exc)}
    finally:
        try:
            client.close()
        except Exception:
            pass
    return out


DB = SocAnalyticsDB(db_path=DB_PATH)
ZABBIX = ZabbixClient(
    ZabbixConfig(
        api_url=ZABBIX_URL,
        username=ZABBIX_USER,
        password=ZABBIX_PASSWORD,
        timeout_sec=20,
    )
)

_COLLECTOR_STOP = threading.Event()
_COLLECTOR_THREAD: Optional[threading.Thread] = None
_TELEGRAM_NOTIFY_THREAD: Optional[threading.Thread] = None


def _severity_text(sev: Any) -> str:
    m = {
        0: "Information",
        1: "Warning",
        2: "Average",
        3: "High",
        4: "Disaster",
    }
    try:
        return m.get(int(sev), "Information")
    except Exception:
        return "Information"


def _coerce_number(val: Any) -> Optional[float]:
    if val is None:
        return None
    try:
        return float(val)
    except Exception:
        return None


def _build_host_snapshot(host_id: Optional[str], items_map: Dict[str, Dict[str, Any]]) -> Tuple[Dict[str, Any], Dict[str, str]]:
    metrics: Dict[str, Any] = {}
    text_vals: Dict[str, str] = {}
    for key in ZABBIX_ITEM_KEYS:
        row = items_map.get(key)
        if not row:
            metrics[key] = None
            continue
        num, txt = ZABBIX.latest_value_for_item(row)
        if txt is not None and num is None:
            text_vals[key] = txt
            metrics[key] = None
        else:
            metrics[key] = num
    if "system.users.num" in metrics and metrics["system.users.num"] is not None:
        try:
            metrics["system.users.num"] = int(float(metrics["system.users.num"]))
        except Exception:
            pass
    if "system.uptime" in metrics and metrics["system.uptime"] is not None:
        try:
            metrics["system.uptime"] = int(float(metrics["system.uptime"]))
        except Exception:
            pass
    net_ok = (
        metrics.get('net.if.in["zttqhuceey"]') is not None or metrics.get('net.if.out["zttqhuceey"]') is not None
    )
    payload = {
        "host_id": host_id,
        "metrics": metrics,
        "text": text_vals,
        "network_status": "UP" if net_ok else "UNKNOWN",
    }
    return payload, text_vals


def _net_derivatives(series: List[Dict[str, Any]]) -> Tuple[List[float], List[float]]:
    in_bps: List[float] = []
    out_bps: List[float] = []
    prev_t: Optional[float] = None
    prev_i: Optional[float] = None
    prev_o: Optional[float] = None
    for row in series:
        t = (row.get("ts_ms") or 0) / 1000.0
        m = (row.get("payload") or {}).get("metrics") or {}
        vi = _coerce_number(m.get('net.if.in["zttqhuceey"]'))
        vo = _coerce_number(m.get('net.if.out["zttqhuceey"]'))
        if prev_t is None or vi is None or vo is None or prev_i is None or prev_o is None:
            in_bps.append(0.0)
            out_bps.append(0.0)
        else:
            dt = t - prev_t
            if dt <= 0:
                in_bps.append(0.0)
                out_bps.append(0.0)
            else:
                in_bps.append(max(0.0, (vi - prev_i) / dt))
                out_bps.append(max(0.0, (vo - prev_o) / dt))
        prev_t, prev_i, prev_o = t, vi, vo
    return in_bps, out_bps


def _memory_stack_points(series: List[Dict[str, Any]]) -> Tuple[List[float], List[float], List[float], List[float]]:
    used_pct: List[float] = []
    cached_pct: List[float] = []
    avail_pct: List[float] = []
    swap_used_pct: List[float] = []
    for row in series:
        m = (row.get("payload") or {}).get("metrics") or {}
        u = _coerce_number(m.get("vm.memory.utilization")) or 0.0
        ab = _coerce_number(m.get("vm.memory.size[available]"))
        cb = _coerce_number(m.get("vm.memory.size[cached]")) or 0.0
        total_est = None
        if ab is not None and u < 99.99:
            total_est = ab / max(1e-9, (100.0 - u) / 100.0)
        if total_est and total_est > 0:
            cp = min(100.0, max(0.0, (cb / total_est) * 100.0))
            ap = min(100.0, max(0.0, (ab / total_est) * 100.0))
            up = min(100.0, max(0.0, 100.0 - ap - cp))
        else:
            cp = 0.0
            ap = max(0.0, 100.0 - u)
            up = u
        spf = _coerce_number(m.get("system.swap.size[,pfree]"))
        su = max(0.0, min(100.0, 100.0 - (spf or 0.0))) if spf is not None else 0.0
        used_pct.append(round(up, 2))
        cached_pct.append(round(cp, 2))
        avail_pct.append(round(ap, 2))
        swap_used_pct.append(round(su, 2))
    return used_pct, cached_pct, avail_pct, swap_used_pct


def build_dashboard_payload(*, hours: int = 24) -> Dict[str, Any]:
    series = DB.get_zabbix_snapshot_series(hours=hours)
    labels = [
        datetime.fromtimestamp((r.get("ts_ms") or 0) / 1000, tz=VN_TZ).strftime("%m-%d %H:%M")
        for r in series
    ]
    def col(k: str) -> List[Optional[float]]:
        out: List[Optional[float]] = []
        for row in series:
            v = (row.get("payload") or {}).get("metrics") or {}
            x = v.get(k)
            out.append(_coerce_number(x) if x is not None else None)
        return out

    net_in_bps, net_out_bps = _net_derivatives(series)
    mem_u, mem_c, mem_a, swap_u = _memory_stack_points(series)

    latest = DB.get_latest_zabbix_snapshot()
    lp = (latest or {}).get("payload") or {}
    lm = lp.get("metrics") or {}

    _debug89_log(
        run_id="soc-server",
        hypothesis_id="H3_NET_KEY",
        location="soc_server.py:build_dashboard_payload",
        message="Latest snapshot metrics key presence (ZeroTier)",
        data={
            "has_net_in": (lm.get('net.if.in["zttqhuceey"]') is not None),
            "has_net_out": (lm.get('net.if.out["zttqhuceey"]') is not None),
            "has_hostname": (lm.get("system.hostname") is not None),
        },
    )

    return {
        "kpis": DB.get_kpis(),
        "latest": {
            "metrics": lm,
            "text": lp.get("text") or {},
            "network_status": lp.get("network_status"),
            "ts_ms": (latest or {}).get("ts_ms"),
        },
        "series": {
            "labels": labels,
            "cpu_util": col("system.cpu.util"),
            "load1": col("system.cpu.load[all,avg1]"),
            "load5": col("system.cpu.load[all,avg5]"),
            "load15": col("system.cpu.load[all,avg15]"),
            "disk_pused": col("vfs.fs.size[/,pused]"),
            "proc_total": col("proc.num"),
            "proc_run": col("proc.num[,,run]"),
            "mem_used_stack": mem_u,
            "mem_cached_stack": mem_c,
            "mem_avail_stack": mem_a,
            "swap_used_stack": swap_u,
            "net_in_bps": net_in_bps,
            "net_out_bps": net_out_bps,
        },
        "alerts": DB.get_recent_zabbix_events(limit=300),
        "severity_distribution": DB.zabbix_severity_distribution(),
    }


def _anomaly_context_block() -> str:
    parts: List[str] = []
    snap = DB.get_latest_zabbix_snapshot()
    if not snap:
        return "No Zabbix snapshot available yet."
    p = snap.get("payload") or {}
    m = p.get("metrics") or {}
    tx = p.get("text") or {}
    cpu = _coerce_number(m.get("system.cpu.util"))
    if cpu is not None and cpu > 80:
        parts.append(f"High CPU utilization: {cpu:.1f}%")
    elif cpu is not None and cpu > 60:
        parts.append(f"Elevated CPU utilization: {cpu:.1f}%")
    ram = _coerce_number(m.get("vm.memory.utilization"))
    if ram is not None and ram > 85:
        parts.append(f"High memory utilization: {ram:.1f}%")
    disk = _coerce_number(m.get("vfs.fs.size[/,pused]"))
    if disk is not None and disk > 85:
        parts.append(f"High disk usage on /: {disk:.1f}%")
    ck = tx.get("vfs.file.cksum[/etc/passwd,sha256]")
    if ck:
        parts.append(f"/etc/passwd SHA256 checksum (monitor for drift): {ck[:32]}…")
    recent = DB.get_recent_zabbix_events(limit=15)
    crit = [e for e in recent if e.get("severity") in ("High", "Disaster", "Average")]
    if crit:
        parts.append("Recent notable alerts:")
        for e in crit[:8]:
            parts.append(
                f"- [{e.get('severity')}] {e.get('trigger_name')} on {e.get('hostname')} ({e.get('status')})"
            )
    if not parts:
        parts.append("No anomalies auto-detected in the latest snapshot; review alerts table for subtle issues.")
    return "\n".join(parts)


def _is_security_question(q: str) -> bool:
    s = (q or "").strip().lower()
    if not s:
        return True
    # Conversational follow-ups (stateless UI); treat as allowed so guard isn't jarring.
    if s in ("có", "co", "ok", "oke", "được", "duoc", "yes", "y", "uh", "ừ", "ua", "chi tiết", "chi tiet", "details", "more"):
        return True
    # System status / health questions are SOC-relevant even if they don't contain "security" keywords.
    if "hệ thống" in s or "he thong" in s or "server" in s or "máy" in s or "may" in s:
        status_needles = (
            "an toàn",
            "an toan",
            "an ninh",
            "security",
            "safe",
            "secure",
            "tình hình",
            "tinh hinh",
            "đang sao",
            "dang sao",
            "sao rồi",
            "sao roi",
            "trục trặc",
            "truc trac",
            "sự cố",
            "su co",
            "lỗi",
            "loi",
            "problem",
            "issues",
            "health",
            "status",
        )
        if any(k in s for k in status_needles):
            return True
    # Allow a wide net of SOC/security topics; reject obviously off-topic chit-chat.
    allow = (
        "soc",
        "ids",
        "suricata",
        "zabbix",
        "lynis",
        "alert",
        "attack",
        "tấn công",
        "bảo mật",
        "security",
        "ioc",
        "mitre",
        "cve",
        "malware",
        "ransom",
        "ddos",
        "xss",
        "sqli",
        "sql injection",
        "csrf",
        "rce",
        "brute",
        "scan",
        "waf",
        "firewall",
        "pfsense",
        "pf sense",
        "snort",
        "suricata rules",
        "iptables",
        "nftables",
        "block",
        "chặn",
        "deny",
        "rate-limit",
        "rate limit",
        "ngăn chặn",
        "ssh",
        "log",
        "incident",
        "forensic",
        "hardening",
        "integrity",
        "checksum",
        "flow",
        "threat",
        # System health in SOC context
        "cpu",
        "ram",
        "memory",
        "disk",
        "ổ đĩa",
        "băng thông",
        "bandwidth",
        "network",
        "mạng",
        "an toàn",
        "an toan",
        "safe",
        "secure",
        "đang sao",
        "sao rồi",
        "tình hình",
    )
    if any(k in s for k in allow):
        return True
    # Very short greetings are allowed but answered in SOC context.
    if s in ("hi", "hello", "chào", "chao", "chào bạn", "xin chào"):
        return True
    return False


def _local_soc_summary(question: str) -> str:
    """
    Local (non-LLM) summary using soc_analytics.db:
    - latest KPIs/metrics
    - latest IDS alert
    - notable Zabbix problems
    """
    latest = DB.get_latest_zabbix_snapshot() or {}
    lp = (latest.get("payload") or {})
    m = (lp.get("metrics") or {})
    k = DB.get_kpis() or {}
    ids_latest = (DB.get_recent_ids_alerts(limit=1) or [{}])[0]
    problems = DB.get_recent_zabbix_events(limit=10) or []
    open_notable = [p for p in problems if (p.get("status") == "PROBLEM" and p.get("severity") in ("Average", "High", "Disaster"))]

    def n(v: Any) -> Optional[float]:
        return _coerce_number(v)

    cpu = n(m.get("system.cpu.util"))
    ram = n(m.get("vm.memory.utilization"))
    disk = n(m.get("vfs.fs.size[/,pused]"))
    net_status = (k.get("network_status") or lp.get("network_status") or "UNKNOWN")

    lines: List[str] = []
    lines.append("Tóm tắt nhanh SOC (local):")
    lines.append(f"- Network: {net_status}")
    if cpu is not None:
        lines.append(f"- CPU: {cpu:.1f}%")
    if ram is not None:
        lines.append(f"- RAM: {ram:.1f}%")
    if disk is not None:
        lines.append(f"- Disk /: {disk:.1f}% used")

    if ids_latest and ids_latest.get("signature"):
        lines.append(
            f"- IDS latest: [{ids_latest.get('severity')}] {ids_latest.get('attack_type')} | {ids_latest.get('src_ip')} -> {ids_latest.get('dest_ip')}"
        )
    if open_notable:
        lines.append("- Zabbix notable (open):")
        for p in open_notable[:3]:
            lines.append(f"  - [{p.get('severity')}] {p.get('trigger_name')} on {p.get('hostname')}")
    else:
        lines.append("- Zabbix notable (open): none")

    # Lightly respond to "an toàn không" by tying to open issues.
    qn = (question or "").lower()
    if any(x in qn for x in ("an toàn", "an toan", "safe", "secure", "hệ thống", "he thong")):
        if ids_latest and ids_latest.get("severity") in ("Critical", "High"):
            lines.append("Đánh giá: đang có IDS alert mức cao → không thể coi là 'an toàn' tuyệt đối; cần điều tra/chặn theo playbook.")
        elif open_notable:
            lines.append("Đánh giá: có cảnh báo Zabbix mức Average/High/Disaster đang mở → cần kiểm tra nguyên nhân (có thể ảnh hưởng an toàn).")
        else:
            lines.append("Đánh giá: không thấy cảnh báo nghiêm trọng đang mở trong DB, nhưng vẫn nên theo dõi IDS/Zabbix theo thời gian thực.")

    return "\n".join(lines)


def _local_soc_details() -> str:
    """More detailed local snapshot for follow-up requests like 'có/chi tiết'."""
    latest = DB.get_latest_zabbix_snapshot() or {}
    lp = (latest.get("payload") or {})
    m = (lp.get("metrics") or {})
    tx = (lp.get("text") or {})
    k = DB.get_kpis() or {}
    ids_latest = (DB.get_recent_ids_alerts(limit=1) or [{}])[0]
    open_events = [e for e in (DB.get_recent_zabbix_events(limit=30) or []) if e.get("status") == "PROBLEM"]

    def n(v: Any) -> Optional[float]:
        return _coerce_number(v)

    cpu = n(m.get("system.cpu.util"))
    load1 = n(m.get("system.cpu.load[all,avg1]"))
    load5 = n(m.get("system.cpu.load[all,avg5]"))
    load15 = n(m.get("system.cpu.load[all,avg15]"))
    ram = n(m.get("vm.memory.utilization"))
    disk = n(m.get("vfs.fs.size[/,pused]"))
    users = m.get("system.users.num")
    uptime = m.get("system.uptime")
    net_status = (k.get("network_status") or lp.get("network_status") or "UNKNOWN")

    out: List[str] = []
    out.append("Chi tiết hệ thống (local):")
    out.append(f"- Network status: {net_status}")
    if uptime is not None:
        out.append(f"- Uptime(s): {uptime}")
    if users is not None:
        out.append(f"- Users: {users}")
    if cpu is not None:
        out.append(f"- CPU util: {cpu:.2f}%")
    if load1 is not None or load5 is not None or load15 is not None:
        out.append(f"- Load avg: {load1 if load1 is not None else '—'} / {load5 if load5 is not None else '—'} / {load15 if load15 is not None else '—'}")
    if ram is not None:
        out.append(f"- RAM util: {ram:.2f}%")
    if disk is not None:
        out.append(f"- Disk / used: {disk:.2f}%")

    ck = tx.get("vfs.file.cksum[/etc/passwd,sha256]")
    if ck:
        out.append(f"- Integrity /etc/passwd sha256: {ck[:16]}…")

    if ids_latest and ids_latest.get("signature"):
        out.append(
            f"- IDS latest: [{ids_latest.get('severity')}] {ids_latest.get('attack_type')} | {ids_latest.get('src_ip')} -> {ids_latest.get('dest_ip')} | action={ids_latest.get('recommended_action')}"
        )
    if open_events:
        out.append("- Zabbix open problems (top 5):")
        for e in open_events[:5]:
            out.append(f"  - [{e.get('severity')}] {e.get('trigger_name')} on {e.get('hostname')}")
    else:
        out.append("- Zabbix open problems: none")
    return "\n".join(out)

def _collect_once(run_id: str) -> Dict[str, int]:
    # #region agent log
    _debug_log(
        run_id=run_id,
        hypothesis_id="H1_API_LOGIN",
        location="soc_server.py:_collect_once",
        message="Collector cycle started",
        data={"pollIntervalSec": POLL_INTERVAL_SEC, "host": ZABBIX_HOST_NAME},
    )
    # #endregion agent log

    token = ZABBIX.login()
    # #region agent log
    _debug_log(
        run_id=run_id,
        hypothesis_id="H1_API_LOGIN",
        location="soc_server.py:_collect_once",
        message="Zabbix login success",
        data={"tokenPresent": bool(token), "authMode": getattr(ZABBIX, "_auth_mode", "unknown")},
    )
    # #endregion agent log

    host_id = ZABBIX.host_id_by_name(ZABBIX_HOST_NAME)
    items_map: Dict[str, Dict[str, Any]] = {}
    if host_id:
        items_map = ZABBIX.items_for_host(host_id, ZABBIX_ITEM_KEYS)

    payload, _ = _build_host_snapshot(host_id, items_map)

    problems = ZABBIX.problem_get(limit=300, min_severity=1)

    # #region agent log
    _debug_log(
        run_id=run_id,
        hypothesis_id="H2_PROBLEM_FORMAT",
        location="soc_server.py:_collect_once",
        message="Fetched problems from Zabbix",
        data={
            "problemCount": len(problems),
            "sampleKeys": list((problems[0] if problems else {}).keys())[:20],
        },
    )
    # #endregion agent log

    upserts = 0
    for p in problems:
        event_id = str(p.get("eventid") or "")
        if not event_id:
            continue
        if DB.is_zabbix_event_user_cleared(event_id):
            continue
        host = ((p.get("hosts") or [{}])[0]).get("name", "unknown")
        name = p.get("name", "Unknown trigger")
        severity = _severity_text(p.get("severity", 0))
        ts_ms = int(float(p.get("clock", time.time())) * 1000)
        status = "PROBLEM" if str(p.get("r_eventid") or "0") == "0" else "RESOLVED"

        prev_analysis = DB.get_zabbix_event_analysis(event_id)
        if prev_analysis:
            analysis = prev_analysis
        else:
            analysis = explain_zabbix_alert(
                {
                    "trigger_name": name,
                    "severity": severity,
                    "hostname": host,
                    "opdata": p.get("opdata", ""),
                    "tags": p.get("tags", []),
                }
            )
        DB.upsert_zabbix_event(
            {
                "event_id": event_id,
                "trigger_id": str(p.get("objectid") or ""),
                "trigger_name": name,
                "severity": severity,
                "hostname": host,
                "status": status,
                "description": p.get("opdata") or name,
                "clock_ms": ts_ms,
                "analysis": analysis,
            }
        )
        upserts += 1

    m = payload.get("metrics") or {}
    DB.insert_metric_point(
        cpu=_coerce_number(m.get("system.cpu.util")),
        ram=_coerce_number(m.get("vm.memory.utilization")),
        net_in=_coerce_number(m.get('net.if.in["zttqhuceey"]')),
    )
    DB.insert_zabbix_snapshot(host_id=host_id, payload=payload)

    # #region agent log
    _debug_log(
        run_id=run_id,
        hypothesis_id="H3_DB_WRITE",
        location="soc_server.py:_collect_once",
        message="Collector cycle completed",
        data={
            "upserts": upserts,
            "hostResolved": bool(host_id),
            "keysFound": len([k for k in ZABBIX_ITEM_KEYS if k in items_map]),
        },
    )
    # #endregion agent log

    _maybe_zabbix_telegram_notify()
    return {"inserted": upserts, "problem_count": len(problems)}


def _maybe_zabbix_telegram_notify() -> None:
    """Send Telegram when TELEGRAM_* env set (same as zabbix_telegram_notifier.py)."""
    token = (os.environ.get("TELEGRAM_BOT_TOKEN") or "").strip()
    chat_id = (os.environ.get("TELEGRAM_CHAT_ID") or "").strip()
    if not token or not chat_id:
        return
    try:
        from zabbix_telegram_notifier import run_cycle

        state_path = Path(__file__).resolve().parent / "zabbix_telegram_notifier.state.json"
        run_cycle(DB, state_path, token, chat_id)
    except Exception:
        logger.exception("Zabbix Telegram notify failed")


def _collector_loop() -> None:
    while not _COLLECTOR_STOP.is_set():
        try:
            _collect_once("collector")
        except Exception as exc:
            # #region agent log
            _debug_log(
                run_id="collector",
                hypothesis_id="H4_RUNTIME_ERROR",
                location="soc_server.py:_collector_loop",
                message="Collector cycle failed",
                data={"error": str(exc)},
            )
            # #endregion agent log
            logger.exception("Collector error")
        _COLLECTOR_STOP.wait(POLL_INTERVAL_SEC)


def _start_collector() -> None:
    global _COLLECTOR_THREAD
    if _COLLECTOR_THREAD and _COLLECTOR_THREAD.is_alive():
        return
    _COLLECTOR_THREAD = threading.Thread(target=_collector_loop, daemon=True)
    _COLLECTOR_THREAD.start()


def _zabbix_telegram_embedded_loop() -> None:
    """Optional: same logic as zabbix_telegram_notifier.py when ZABBIX_TELEGRAM_EMBEDDED=1."""
    token = (os.environ.get("TELEGRAM_BOT_TOKEN") or "").strip()
    chat_id = (os.environ.get("TELEGRAM_CHAT_ID") or "").strip()
    if not token or not chat_id:
        return
    try:
        interval = max(8, int(os.environ.get("ZABBIX_NOTIFY_INTERVAL_SEC", "20")))
    except Exception:
        interval = 20
    from zabbix_telegram_notifier import run_cycle

    state_path = Path(__file__).resolve().parent / "zabbix_telegram_notifier.state.json"
    logger.info("Embedded Zabbix→Telegram loop started (interval=%ss)", interval)
    while True:
        try:
            run_cycle(DB, state_path, token, chat_id)
        except Exception:
            logger.exception("Embedded Zabbix Telegram cycle failed")
        time.sleep(interval)


def _start_embedded_zabbix_telegram() -> None:
    global _TELEGRAM_NOTIFY_THREAD
    if os.environ.get("ZABBIX_TELEGRAM_EMBEDDED", "").strip().lower() not in ("1", "true", "yes", "on"):
        return
    if not (os.environ.get("TELEGRAM_BOT_TOKEN") or "").strip():
        return
    if _TELEGRAM_NOTIFY_THREAD and _TELEGRAM_NOTIFY_THREAD.is_alive():
        return
    _TELEGRAM_NOTIFY_THREAD = threading.Thread(target=_zabbix_telegram_embedded_loop, daemon=True)
    _TELEGRAM_NOTIFY_THREAD.start()


@app.route("/health", methods=["GET"])
def health() -> Any:
    # #region agent log
    try:
        _debug44_log(
            run_id="pre",
            hypothesis_id="H1_SOC_URL_CONNECT",
            location="soc_server.py:/health",
            message="Health endpoint hit",
            data={
                "remote_addr": request.remote_addr,
                "x_forwarded_for": request.headers.get("X-Forwarded-For"),
                "host": request.headers.get("Host"),
            },
        )
    except Exception:
        pass
    # #endregion agent log
    return jsonify({"status": "ok", "time": datetime.now().isoformat()}), 200


@app.route("/log", methods=["POST"])
def ingest_suricata_log() -> Any:
    """
    Receives Suricata eve.json event entries.
    Returns JSON for forwarder compatibility.
    """
    data = request.get_json(force=True) if request.is_json else {}
    if SOC_INGEST_TOKEN:
        got = request.headers.get("X-SOC-Token", "")
        if got != SOC_INGEST_TOKEN:
            _agent_log(
                run_id="ids",
                hypothesis_id="H1_TOKEN",
                location="soc_server.py:/log",
                message="Rejected ingest due to token mismatch",
                data={"hasToken": bool(got)},
            )
            return jsonify({"status": "rejected"}), 403

    et = str(data.get("event_type") or "").strip()
    # #region agent log
    _agent_log(
        run_id="ids",
        hypothesis_id="H2_INGEST",
        location="soc_server.py:/log",
        message="Received Suricata event",
        data={"event_type": et, "keys": list(data.keys())[:20]},
    )
    # #endregion agent log

    if not et:
        return jsonify({"status": "skipped"}), 200

    try:
        if et == "alert":
            analysis = _ids_quick_ai(data)
            DB.insert_alert(data, analysis=analysis)
            DB.label_flows_for_alert(alert_log_data=data)
            return (
                jsonify(
                    {
                        "status": "processed",
                        "attack_type": analysis.get("attack_type"),
                        "severity": analysis.get("severity"),
                        "recommended_action": analysis.get("recommended_action"),
                    }
                ),
                200,
            )
        if et == "flow":
            DB.insert_flow(data)
            return jsonify({"status": "stored"}), 200
        if et == "dns":
            DB.insert_dns(data)
            return jsonify({"status": "stored"}), 200
        if et == "http":
            DB.insert_http(data)
            return jsonify({"status": "stored"}), 200
        if et == "tls":
            DB.insert_tls(data)
            return jsonify({"status": "stored"}), 200
        if et == "fileinfo":
            DB.insert_fileinfo(data)
            return jsonify({"status": "stored"}), 200
        if et == "stats":
            DB.insert_stats(data)
            return jsonify({"status": "stored"}), 200
        return jsonify({"status": "skipped"}), 200
    except Exception as exc:
        _agent_log(
            run_id="ids",
            hypothesis_id="H3_INGEST_ERR",
            location="soc_server.py:/log",
            message="Ingest failed",
            data={"error": str(exc), "event_type": et},
        )
        return jsonify({"status": "error"}), 500


@app.route("/ids/alerts", methods=["GET"])
def ids_alerts() -> Any:
    try:
        limit = int(request.args.get("limit", "200"))
        limit = max(1, min(limit, 1000))
    except Exception:
        limit = 200
    rows = DB.get_recent_ids_alerts(limit=limit)
    # #region agent log
    _agent_log(
        run_id="ids",
        hypothesis_id="H4_IDS_LIST",
        location="soc_server.py:/ids/alerts",
        message="Served IDS alerts",
        data={"count": len(rows), "limit": limit},
    )
    # #endregion agent log
    return jsonify({"alerts": rows}), 200


@app.route("/analytics/stats", methods=["GET"])
def analytics_stats() -> Any:
    try:
        window_minutes = int(request.args.get("windowMinutes", "60"))
        bucket_minutes = int(request.args.get("bucketMinutes", "5"))
        window_minutes = max(5, min(window_minutes, 24 * 60))
        bucket_minutes = max(1, min(bucket_minutes, 60))
    except Exception:
        window_minutes, bucket_minutes = 60, 5
    return jsonify(DB.analytics_dashboard(window_minutes=window_minutes, bucket_minutes=bucket_minutes)), 200


@app.route("/api/lynis/scan", methods=["POST"])
def lynis_scan_sse() -> Any:
    """
    Stream Lynis remote audit over SSH as Server-Sent Events.
    JSON body: target_ip, user, ssh_pass, sudo_pass, port (optional).
    """
    if not LYNIS_REMOTE_ENABLED:
        return jsonify({"error": "Lynis remote scan disabled (set LYNIS_REMOTE_ENABLED=1)"}), 403

    data = request.get_json(force=True) if request.is_json else {}
    target_ip = (data.get("target_ip") or "").strip()
    user = (data.get("user") or "").strip()
    ssh_pass = data.get("ssh_pass") or ""
    sudo_pass = data.get("sudo_pass") or ""
    try:
        port = int(data.get("port") or 22)
    except Exception:
        port = 22

    if not target_ip or not user:
        return jsonify({"error": "target_ip and user are required"}), 400

    def generate() -> Any:
        for chunk in iter_sse_lynis_scan(
            target_ip=target_ip,
            user=user,
            ssh_pass=ssh_pass,
            sudo_pass=sudo_pass,
            port=port,
        ):
            yield chunk

    # Note: Do not set "Connection" — WSGI (PEP 3333) forbids hop-by-hop headers; Waitress raises AssertionError.
    headers = {
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
    }
    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream; charset=utf-8",
        headers=headers,
    )


@app.route("/api/integrity/checksums", methods=["POST"])
def api_integrity_checksums() -> Any:
    """
    Fetch file SHA256 checksums from Linux server via SSH (more accurate than Zabbix for protected files).
    JSON body: target_ip, user, ssh_pass, sudo_pass, port(optional), files(optional).
    """
    data = request.get_json(force=True) if request.is_json else {}
    target_ip = (data.get("target_ip") or "").strip()
    user = (data.get("user") or "").strip()
    ssh_pass = data.get("ssh_pass") or ""
    sudo_pass = data.get("sudo_pass") or ""
    try:
        port = int(data.get("port") or 22)
    except Exception:
        port = 22
    files = data.get("files")
    if not isinstance(files, list) or not files:
        files = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts"]

    if not target_ip or not user:
        return jsonify({"ok": False, "error": "target_ip and user are required"}), 400

    # #region agent log
    _debug44_log(
        run_id="pre",
        hypothesis_id="H4_INTEGRITY_SSH",
        location="soc_server.py:/api/integrity/checksums",
        message="Integrity checksum request",
        data={"target_ip": target_ip, "user": user, "port": port, "file_count": len(files)},
    )
    # #endregion agent log

    res = _ssh_sha256_files(
        target_ip=target_ip,
        user=user,
        ssh_pass=ssh_pass,
        sudo_pass=sudo_pass,
        port=port,
        files=[str(x) for x in files],
    )
    return jsonify({"ok": True, "checksums": res}), 200


@app.route("/api/dashboard", methods=["GET"])
def api_dashboard() -> Any:
    try:
        hours = int(request.args.get("hours", "24"))
        hours = max(1, min(hours, 168))
    except Exception:
        hours = 24
    return jsonify(build_dashboard_payload(hours=hours)), 200


@app.route("/collector/run", methods=["POST"])
def run_collector_once() -> Any:
    try:
        res = _collect_once("manual")
        return jsonify({"status": "ok", **res}), 200
    except Exception as exc:
        # #region agent log
        _debug_log(
            run_id="manual",
            hypothesis_id="H4_RUNTIME_ERROR",
            location="soc_server.py:/collector/run",
            message="Manual collector failed",
            data={"error": str(exc)},
        )
        # #endregion agent log
        return jsonify({"status": "error", "error": str(exc)}), 500


@app.route("/alerts", methods=["GET"])
def alerts() -> Any:
    return jsonify({"alerts": DB.get_recent_zabbix_events(limit=200)}), 200


@app.route("/kpis", methods=["GET"])
def kpis() -> Any:
    return jsonify(DB.get_kpis()), 200


@app.route("/top-rules", methods=["GET"])
def top_rules() -> Any:
    return jsonify({"rules": DB.get_top_rule_violations(limit=5)}), 200


@app.route("/metrics", methods=["GET"])
def metrics() -> Any:
    return jsonify(DB.get_metrics_series(minutes=60)), 200


@app.route("/history", methods=["GET"])
def history() -> Any:
    severity = request.args.get("severity")
    return jsonify({"events": DB.get_history_events(limit=500, severity=severity)}), 200


@app.route("/api/events/clear", methods=["POST"])
def api_events_clear() -> Any:
    """Clear stored events: scope=zabbix (EVENT LOG / KPI totals) or scope=ids (Suricata alert_events)."""
    data = request.get_json(force=True) if request.is_json else {}
    scope = (data.get("scope") or "").strip().lower()
    try:
        if scope == "zabbix":
            n = DB.delete_all_zabbix_events()
            return jsonify({"ok": True, "deleted": n, "scope": "zabbix"}), 200
        if scope == "ids":
            n = DB.delete_all_alert_events()
            return jsonify({"ok": True, "deleted": n, "scope": "ids"}), 200
    except Exception as exc:
        logger.exception("api_events_clear failed")
        return jsonify({"ok": False, "error": str(exc)}), 500
    return jsonify({"ok": False, "error": "scope must be zabbix or ids"}), 400


@app.route("/chat", methods=["POST"])
def chat() -> Any:
    data = request.get_json(force=True) if request.is_json else {}
    question = (data.get("message") or "").strip()
    if not question:
        return jsonify({"error": "message is required"}), 400

    anomaly = _anomaly_context_block()
    latest = DB.get_recent_zabbix_events(limit=1)
    ctx = latest[0] if latest else {}
    # Optional client-provided context (e.g., IDS tab). Keep small; do not store secrets.
    extra_ctx = (data.get("context") or "").strip()
    ids_latest = (DB.get_recent_ids_alerts(limit=1) or [{}])[0]
    latest_snapshot = DB.get_latest_zabbix_snapshot() or {}
    snap_metrics = (latest_snapshot.get("payload") or {}).get("metrics") or {}
    # #region agent log
    _agent_log(
        run_id="chat",
        hypothesis_id="H6_CHAT_INPUT",
        location="soc_server.py:/chat",
        message="Chat request received",
        data={
            "question_len": len(question),
            "has_extra_context": bool(extra_ctx),
            "ids_latest_present": bool(ids_latest and ids_latest.get("signature")),
            "mode": SOC_CHAT_MODE,
        },
    )
    # #endregion agent log
    # Enforce: only security-related answers (but be helpful when unclear).
    is_sec = _is_security_question(question)
    # #region agent log
    _debug44_log(
        run_id="pre",
        hypothesis_id="H9_CHAT_GUARD",
        location="soc_server.py:/chat",
        message="Guard evaluated",
        data={"is_security": bool(is_sec), "question_len": len(question), "preview": question[:60]},
    )
    # #endregion agent log
    if not is_sec:
        msg = (
            "Mình đang ở chế độ **SOC/security-only** nên không trả lời chủ đề ngoài bảo mật.\n\n"
            "Nếu bạn muốn hỏi bảo mật, thử hỏi theo 1 trong các mẫu này:\n"
            "- “Cảnh báo Suricata/XSS này nên chặn thế nào trên pfSense?”\n"
            "- “Cho playbook xử lý SQLi/RCE với bước chặn + log cần xem”\n"
            "- “Tóm tắt cảnh báo gần đây trong hệ thống và mức độ nguy hiểm”"
        )
        return jsonify({"response": msg, "mode": "guard"}), 200

    # Better local fallback: if question is about system health / safety / recent alerts, summarize from DB.
    q_low = (question or "").lower()
    if q_low.strip() in ("có", "co", "ok", "oke", "chi tiết", "chi tiet", "details", "more", "yes", "y", "được", "duoc"):
        local_answer = _local_soc_details()
    elif any(k in q_low for k in ("cpu", "ram", "memory", "disk", "network", "mạng", "an toàn", "an toan", "cảnh báo", "alert", "tình hình", "sao rồi", "đang sao")):
        local_answer = _local_soc_summary(question)
    else:
        local_answer = explain_zabbix_alert(
            {
                "trigger_name": ctx.get("trigger_name", "No trigger"),
                "severity": ctx.get("severity", "Information"),
                "hostname": ctx.get("hostname", "unknown"),
                "opdata": ctx.get("description", ""),
                "user_question": question,
            }
        )

    # Short identity intent: reply naturally, no long incident template.
    q_norm = question.strip().lower()
    if re.fullmatch(r"(bạn là ai|ban la ai|ai vậy|ai vay|who are you)\??", q_norm):
        short_intro = (
            "Tôi là một Analyst SOC (Security Operations Center) AI, có trách nhiệm phân tích và đánh giá các tín hiệu an ninh, "
            "cũng như cung cấp hướng dẫn và hỗ trợ cho quá trình xử lý các sự kiện an ninh."
        )
        # #region agent log
        _agent_log(
            run_id="chat",
            hypothesis_id="H10_INTENT_INTRO",
            location="soc_server.py:/chat",
            message="Matched short intro intent",
            data={"question": q_norm},
        )
        # #endregion agent log
        return jsonify({"response": short_intro, "mode": "intent"}), 200

    if SOC_CHAT_MODE == "llm":
        try:
            # #region agent log
            _debug44_log(
                run_id="pre",
                hypothesis_id="H10_CHAT_LLM",
                location="soc_server.py:/chat",
                message="LLM mode requested",
                data={
                    "has_gemini_key": bool(os.environ.get("GEMINI_API_KEY")),
                    "has_groq_key": bool(os.environ.get("GROQ_API_KEY")),
                    "has_openrouter_key": bool(os.environ.get("OPENROUTER_API_KEY")),
                },
            )
            # #endregion agent log
            prompt = (
                "You are a SOC AI analyst. Answer in natural Vietnamese, concise and practical.\n"
                "Rules:\n"
                "- Keep answer short (2-6 sentences unless user asks for detail).\n"
                "- Focus on security context and current system signals.\n"
                "- Avoid rigid report templates unless explicitly requested.\n\n"
                f"Recent anomaly signals:\n{anomaly}\n\n"
                f"Latest alert (if any): {json.dumps(ctx, ensure_ascii=False)}\n\n"
                f"Latest IDS alert (if any): {json.dumps(ids_latest, ensure_ascii=False)}\n\n"
                f"Latest system metrics (if any): {json.dumps(snap_metrics, ensure_ascii=False)}\n\n"
            )
            if extra_ctx:
                prompt += f"Client context:\n{extra_ctx}\n\n"
            prompt += f"Analyst question: {question}"
            answer = route_llm(prompt, task_type="analysis", max_tokens=260)
            # #region agent log
            _agent_log(
                run_id="chat",
                hypothesis_id="H7_CHAT_OUTPUT",
                location="soc_server.py:/chat",
                message="LLM response returned",
                data={"answer_len": len(answer or ""), "source": "llm"},
            )
            # #endregion agent log
            return jsonify({"response": answer, "mode": "llm", "context": anomaly}), 200
        except Exception:
            # #region agent log
            try:
                _debug44_log(
                    run_id="pre",
                    hypothesis_id="H10_CHAT_LLM",
                    location="soc_server.py:/chat",
                    message="LLM failed; using local fallback",
                    data={"note": "check provider keys / network"},
                )
            except Exception:
                pass
            _agent_log(
                run_id="chat",
                hypothesis_id="H7_CHAT_OUTPUT",
                location="soc_server.py:/chat",
                message="LLM failed, using local fallback",
                data={"source": "local-fallback"},
            )
            # #endregion agent log
            return jsonify({"response": local_answer, "mode": "local-fallback", "context": anomaly}), 200

    # #region agent log
    _agent_log(
        run_id="chat",
        hypothesis_id="H7_CHAT_OUTPUT",
        location="soc_server.py:/chat",
        message="Local response returned",
        data={"answer_len": len(local_answer or ""), "source": "local"},
    )
    # #endregion agent log
    return jsonify({"response": local_answer, "mode": "local", "context": anomaly}), 200


@app.route("/", methods=["GET"])
def root() -> Any:
    html = Path(__file__).with_name("dashboard.html")
    if html.exists():
        return html.read_text(encoding="utf-8"), 200, {"Content-Type": "text/html; charset=utf-8"}
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    _start_collector()
    _start_embedded_zabbix_telegram()
    app.run(host="0.0.0.0", port=5000, debug=False)


_start_collector()
_start_embedded_zabbix_telegram()
