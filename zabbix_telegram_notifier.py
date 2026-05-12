#!/usr/bin/env python3
"""
Poll SOC SQLite (zabbix_events) and send Telegram for Linux/Zabbix alerts only.
Suricata IDS: suricata_forwarder.py sends Telegram when TELEGRAM_* is on the sensor (burst-deduped).
Optional soc_server POST /log IDS Telegram: set IDS_TELEGRAM_FROM_SOC=1 on the SOC host (default 0; avoid both paths or you get duplicate chats).

Sends once per (event_id, status) so both PROBLEM and RESOLVED are delivered
if the collector updates the row (fixes "only RESOLVED in DB" missing Telegram).

Environment:
  TELEGRAM_BOT_TOKEN            (uu tien; neu trong thi dung gia tri mac dinh trong file)
  TELEGRAM_CHAT_ID              (uu tien; neu trong thi dung gia tri mac dinh trong file)
  SOC_ANALYTICS_DB_PATH         (optional, default: soc_analytics.db)
  ZABBIX_NOTIFY_INTERVAL_SEC    (default: 15)
  ZABBIX_NOTIFY_MIN_SEVERITY    (default: Information) — chỉ gửi từ mức đó trở lên (vd. Warning bỏ Information)

Run:
  set TELEGRAM_BOT_TOKEN=...
  set TELEGRAM_CHAT_ID=...
  python zabbix_telegram_notifier.py
"""

from __future__ import annotations

import html
import json
import logging
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Set

import requests

from soc_db import SocAnalyticsDB, ts_ms_to_vn_iso

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("ZabbixTelegramNotifier")

DEFAULT_INTERVAL = 15
STATE_NAME = "zabbix_telegram_notifier.state.json"

# Lab default (khi khong set bien moi truong — vd. Waitress khong ke thua .bat). Doi token neu da lo.
_DEFAULT_TELEGRAM_BOT_TOKEN = "8784905578:AAENtI143ed3qPMsaQverjfPIyXsjxYSNb4"
_DEFAULT_TELEGRAM_CHAT_ID = "6929846070"


def telegram_credentials() -> tuple[str, str]:
    """TELEGRAM_* tu env; neu thieu thi dung hang mac dinh trong file."""
    return (
        (os.environ.get("TELEGRAM_BOT_TOKEN") or _DEFAULT_TELEGRAM_BOT_TOKEN).strip(),
        (os.environ.get("TELEGRAM_CHAT_ID") or _DEFAULT_TELEGRAM_CHAT_ID).strip(),
    )

# ── Severity ranking ────────────────────────────────────────────────────────
_SEVERITY_RANK = {
    "not classified": 0,
    "information":    1,
    "warning":        2,
    "average":        3,
    "high":           4,
    "disaster":       5,
}

# ── Severity icon (colored circle / symbol) ─────────────────────────────────
_SEVERITY_ICON = {
    "not classified": "⬜",
    "information":    "🔵",
    "warning":        "🟡",
    "average":        "🟠",
    "high":           "🔴",
    "disaster":       "🚨",
}

# ── Status icon ──────────────────────────────────────────────────────────────
_STATUS_ICON = {
    "PROBLEM":  "🔴",
    "RESOLVED": "✅",
}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _severity_rank(name: str) -> int:
    """Unknown / odd Zabbix labels default to Warning tier so alerts are not dropped."""
    return _SEVERITY_RANK.get((name or "").strip().lower(), 2)


def _sev_icon(sev: str) -> str:
    return _SEVERITY_ICON.get((sev or "").strip().lower(), "⬜")


def _status_icon(status: str) -> str:
    return _STATUS_ICON.get((status or "").strip().upper(), "⬜")


def _min_severity_rank() -> int:
    raw = (os.environ.get("ZABBIX_NOTIFY_MIN_SEVERITY") or "Information").strip().lower()
    return _SEVERITY_RANK.get(raw, 1)


def _is_ids_or_suricata_trigger(name: str) -> bool:
    """Chỉ lọc trigger IDS/Suricata thật — tránh chuỗi con ('et open', …) làm rơi cảnh báo Linux/Zabbix."""
    t = (name or "").lower()
    if not t:
        return False
    if "suricata" in t or "eve.json" in t:
        return True
    if "suricata ids" in t or "ids alert" in t:
        return True
    if "emerging threat" in t:
        return True
    if re.search(r"\bsnort\b", t):
        return True
    if re.search(r"\bet\s+open\b", t):
        return True
    return False


def _load_state(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        return {"sent_keys": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {"sent_keys": []}
        data.setdefault("sent_keys", [])
        # migrate legacy
        if not data["sent_keys"] and data.get("notified_problem"):
            for eid in data.get("notified_problem") or []:
                data["sent_keys"].append(f"{eid}|PROBLEM")
        return data
    except Exception:
        return {"sent_keys": []}


def _save_state(path: Path, state: Dict[str, Any]) -> None:
    path.write_text(json.dumps(state, ensure_ascii=False, indent=0), encoding="utf-8")


def _telegram_send(token: str, chat_id: str, text: str) -> bool:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        # Thử HTML trước; Telegram 400 (bad entity) → gửi lại không parse_mode.
        payloads: List[Dict[str, Any]] = [
            {
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            },
            {"chat_id": chat_id, "text": text, "disable_web_page_preview": True},
        ]
        last_err = ""
        for body in payloads:
            r = requests.post(url, json=body, timeout=35)
            if r.status_code == 200:
                return True
            last_err = (r.text or "")[:500]
            if r.status_code == 400 and body.get("parse_mode") == "HTML":
                logger.warning("Telegram từ chối HTML, thử plain text: %s", last_err)
                continue
            logger.error("Telegram HTTP %s: %s", r.status_code, last_err)
            return False
        return False
    except Exception as exc:
        logger.error("Telegram send failed: %s", exc)
        return False


def _wall_clock_vn(ms: int) -> str:
    iso = ts_ms_to_vn_iso(ms)
    if not iso:
        return "—"
    # "2026-04-02T22:41:11+07:00" → "2026-04-02 22:41:11 (UTC+7)"
    part = iso.replace("T", " ")
    if "+" in part:
        part = part.split("+", 1)[0].strip()
    return f"{part} (UTC+7)"


def _format_soc_message(ev: Dict[str, Any]) -> str:
    """
    Professional NOC/SOC Telegram HTML alert.

    Layout:
      {status_icon} [STATUS] SOC / Zabbix
      ▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔
      🕐 Time      ...
      🖥️ Host      ...
      {sev_icon} Severity  ...
      📋 Trigger
      <trigger name>
      ▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔
      🔖 Trigger ID  <code>...</code>
      🆔 Event ID    <code>...</code>
      📊 Detail      (optional)
      <code>...</code>
    """
    host     = html.escape(str(ev.get("hostname")     or "—"))
    sev      = str(ev.get("severity")                 or "—")
    st       = str(ev.get("status")                   or "—").strip().upper()
    trig     = html.escape(str(ev.get("trigger_name") or "—"))
    tid      = html.escape(str(ev.get("trigger_id")   or "—"))
    eid      = html.escape(str(ev.get("event_id")     or "—"))
    ts       = _wall_clock_vn(int(ev.get("clock_ms")  or 0))

    sev_icon = _sev_icon(sev)
    st_icon  = _status_icon(st)
    sev_esc  = html.escape(sev.title())
    st_esc   = html.escape(st)
    ts_esc   = html.escape(ts)

    # Optional detail block — skip if identical to trigger name
    desc = ev.get("description")
    detail_block = ""
    if (
        desc
        and str(desc).strip()
        and str(desc).strip() != str(ev.get("trigger_name") or "").strip()
    ):
        detail_block = (
            "\n\n📊 <b>Detail</b>\n"
            f"<code>{html.escape(str(desc).strip())}</code>"
        )

    return (
        f"{st_icon} <b>[{st_esc}] SOC / Zabbix</b>\n"
        "▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔\n"
        f"🕐 <b>Time</b>      {ts_esc}\n"
        f"🖥️ <b>Host</b>      {host}\n"
        f"{sev_icon} <b>Severity</b>  {sev_esc}\n"
        f"📋 <b>Trigger</b>\n{trig}\n"
        "▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔\n"
        f"🔖 Trigger ID  <code>{tid}</code>\n"
        f"🆔 Event ID    <code>{eid}</code>"
        f"{detail_block}"
    )


# ── DB fetch ─────────────────────────────────────────────────────────────────

def _fetch_recent_events(db: SocAnalyticsDB, limit: int = 500) -> List[Dict[str, Any]]:
    conn = db.connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT event_id, trigger_id, trigger_name, severity, hostname, status, description, clock_ms
        FROM zabbix_events
        ORDER BY clock_ms DESC
        LIMIT ?
        """,
        (limit,),
    )
    out: List[Dict[str, Any]] = []
    for r in cur.fetchall():
        out.append(
            {
                "event_id":    r["event_id"],
                "trigger_id":  r["trigger_id"],
                "trigger_name": r["trigger_name"],
                "severity":    r["severity"],
                "hostname":    r["hostname"],
                "status":      r["status"],
                "description": r["description"],
                "clock_ms":    int(r["clock_ms"] or 0),
            }
        )
    return out


# ── Main cycle ───────────────────────────────────────────────────────────────

def run_cycle(
    db: SocAnalyticsDB,
    state_path: Path,
    token: str,
    chat_id: str,
) -> None:
    state = _load_state(state_path)
    sent: Set[str] = set(str(x) for x in (state.get("sent_keys") or []) if x)
    sent_before = len(sent)
    min_rank = _min_severity_rank()
    min_label = (os.environ.get("ZABBIX_NOTIFY_MIN_SEVERITY") or "Information").strip()

    events = _fetch_recent_events(db)
    # Oldest first so PROBLEM tends to notify before RESOLVED for same incident
    events = list(reversed(events))

    candidates = 0
    skipped_sev = 0
    skipped_ids = 0
    skipped_dup = 0
    skipped_bad = 0

    for ev in events:
        eid = str(ev.get("event_id") or "").strip()
        st = str(ev.get("status") or "").strip().upper()
        if not eid or st not in ("PROBLEM", "RESOLVED"):
            skipped_bad += 1
            continue

        name = str(ev.get("trigger_name") or "")
        if _is_ids_or_suricata_trigger(name):
            skipped_ids += 1
            continue

        sev = str(ev.get("severity") or "")
        if _severity_rank(sev) < min_rank:
            skipped_sev += 1
            continue

        key = f"{eid}|{st}"
        if key in sent:
            skipped_dup += 1
            continue

        candidates += 1
        text = _format_soc_message(ev)
        if _telegram_send(token, chat_id, text):
            sent.add(key)
            label = (name[:72] + "…") if len(name) > 72 else name
            logger.info("Telegram sent | %s | %s", key, label)

    sent_after = len(sent)
    new_keys = sent_after - sent_before
    if new_keys:
        logger.info(
            "Zabbix->Telegram: da gui %d tin moi | DB_events=%d | min_severity=%s (rank>=%d)",
            new_keys,
            len(events),
            min_label,
            min_rank,
        )
    elif events:
        logger.info(
            "Zabbix->Telegram: khong co tin moi | DB_events=%d | min_severity=%s (rank>=%d) | "
            "skip: sev=%d ids_filter=%d dup=%d bad_status=%d | candidates=%d",
            len(events),
            min_label,
            min_rank,
            skipped_sev,
            skipped_ids,
            skipped_dup,
            skipped_bad,
            candidates,
        )

    state["sent_keys"] = sorted(sent)[-12000:]
    _save_state(state_path, state)


def main() -> None:
    token, chat_id = telegram_credentials()
    if not token or not chat_id:
        logger.error("Telegram token/chat empty after defaults")
        sys.exit(2)

    db_path = os.environ.get("SOC_ANALYTICS_DB_PATH", "").strip()
    if not db_path:
        db_path = str(Path(__file__).resolve().parent / "soc_analytics.db")

    db = SocAnalyticsDB(db_path=db_path)
    try:
        conn = db.connect()
        cur  = conn.cursor()
        cur.execute("SELECT COUNT(1) FROM zabbix_events")
        _n = int(cur.fetchone()[0] or 0)
        logger.info("Connected to SQLite | zabbix_events rows=%s", _n)
    except Exception as exc:
        logger.warning("Could not count zabbix_events: %s", exc)

    try:
        interval = max(5, int(os.environ.get("ZABBIX_NOTIFY_INTERVAL_SEC", str(DEFAULT_INTERVAL))))
    except Exception:
        interval = DEFAULT_INTERVAL

    state_path = Path(__file__).resolve().parent / STATE_NAME

    logger.info(
        "SOC Zabbix Telegram | db=%s | interval=%ss | min_severity=%s",
        db_path,
        interval,
        os.environ.get("ZABBIX_NOTIFY_MIN_SEVERITY", "Information"),
    )

    while True:
        try:
            run_cycle(db, state_path, token, chat_id)
        except Exception as exc:
            logger.exception("cycle error: %s", exc)
        time.sleep(interval)


if __name__ == "__main__":
    main()