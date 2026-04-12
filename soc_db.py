import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# #region debug-3adea5 helpers
_DEBUG3_LOG_PATH = Path(__file__).resolve().parent / "debug-3adea5.log"
_DEBUG3_SESSION_ID = "3adea5"
_DEBUG3_FLOW_DEBUGGED = False


def _debug3_log(*, runId: str, hypothesisId: str, location: str, message: str, data: Dict[str, Any]) -> None:
    global _DEBUG3_FLOW_DEBUGGED
    payload = {
        "sessionId": _DEBUG3_SESSION_ID,
        "runId": runId,
        "hypothesisId": hypothesisId,
        "location": location,
        "message": message,
        "data": data,
        "timestamp": int(datetime.now().timestamp() * 1000),
    }
    try:
        _DEBUG3_LOG_PATH.open("a", encoding="utf-8").write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        pass

# #endregion debug-3adea5 helpers


def utc_ms_now() -> int:
    return int(datetime.now(tz=timezone.utc).timestamp() * 1000)


# Display timestamps for UI / API (Vietnam UTC+7, no DST)
VN_TZ = timezone(timedelta(hours=7))


def ts_ms_to_vn_iso(ms: Any) -> str:
    try:
        m = int(ms or 0)
        if m <= 0:
            return ""
        return datetime.fromtimestamp(m / 1000.0, tz=VN_TZ).isoformat()
    except Exception:
        return ""


def parse_int(x: Any, default: Optional[int] = None) -> Optional[int]:
    try:
        if x is None:
            return default
        return int(x)
    except Exception:
        return default


def parse_float(x: Any, default: Optional[float] = None) -> Optional[float]:
    try:
        if x is None:
            return default
        return float(x)
    except Exception:
        return default


def safe_text(x: Any, default: str = "") -> str:
    try:
        if x is None:
            return default
        return str(x)
    except Exception:
        return default


def iso_to_ms(ts: Any) -> Optional[int]:
    """
    Suricata eve.json often uses ISO8601 strings. We store all timestamps as UTC epoch ms.
    """
    if ts is None:
        return None
    try:
        if isinstance(ts, (int, float)):
            # Assume already epoch seconds (or ms). Best-effort.
            if ts > 10_000_000_000:  # ms
                return int(ts)
            return int(ts * 1000)
        s = str(ts).strip()
        # Handle trailing 'Z'
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        # fromisoformat supports "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except Exception:
        return None


def compute_flow_key(
    *,
    src_ip: str,
    src_port: Any,
    dest_ip: str,
    dest_port: Any,
    proto: str,
) -> str:
    # Simple deterministic key used to link flow<->alert.
    return f"{src_ip}:{parse_int(src_port, -1)}->{dest_ip}:{parse_int(dest_port, -1)}:{(proto or '').lower()}"


@dataclass
class DbConfig:
    db_path: str


class SocAnalyticsDB:
    def __init__(self, *, db_path: str):
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None

    def connect(self) -> sqlite3.Connection:
        if self._conn is not None:
            return self._conn
        p = Path(self.db_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        self._conn = conn
        self._init_schema(conn)
        return conn

    def _init_schema(self, conn: sqlite3.Connection) -> None:
        cur = conn.cursor()
        # Events (alerts + flows + other)
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS flow_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts_ms INTEGER NOT NULL,
              src_ip TEXT NOT NULL,
              dest_ip TEXT NOT NULL,
              src_port INTEGER,
              dest_port INTEGER,
              proto TEXT,
              bytes_toserver REAL,
              pkts_toserver REAL,
              flow_duration REAL,
              state TEXT,
              flow_key TEXT,
              labeled_status TEXT DEFAULT 'unlabeled', -- unlabeled | normal | malicious
              label_source TEXT, -- alert | pseudo
              updated_at_ms INTEGER
            );
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_flow_events_ts ON flow_events(ts_ms);
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_flow_events_key_ts ON flow_events(flow_key, ts_ms);
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS alert_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts_ms INTEGER NOT NULL,
              src_ip TEXT,
              dest_ip TEXT,
              src_port INTEGER,
              dest_port INTEGER,
              proto TEXT,
              signature TEXT,
              category TEXT,
              severity TEXT,
              gid INTEGER,
              sid INTEGER,
              rev INTEGER,
              attack_type TEXT,
              confidence TEXT,
              recommended_action TEXT,
              telegram_sent INTEGER DEFAULT 0
            );
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_alert_events_ts ON alert_events(ts_ms);
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS dns_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts_ms INTEGER NOT NULL,
              src_ip TEXT,
              query TEXT,
              rrtype TEXT,
              rcode TEXT,
              host TEXT
            );
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_dns_ts ON dns_events(ts_ms);")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS http_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts_ms INTEGER NOT NULL,
              src_ip TEXT,
              hostname TEXT,
              http_method TEXT,
              status INTEGER,
              user_agent TEXT
            );
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_http_ts ON http_events(ts_ms);")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS tls_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts_ms INTEGER NOT NULL,
              src_ip TEXT,
              sni TEXT,
              tls_version TEXT
            );
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_tls_ts ON tls_events(ts_ms);")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS fileinfo_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts_ms INTEGER NOT NULL,
              src_ip TEXT,
              filename TEXT,
              mime_type TEXT,
              size_bytes INTEGER,
              source TEXT
            );
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_file_ts ON fileinfo_events(ts_ms);")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS stats_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts_ms INTEGER NOT NULL,
              packet_drops REAL,
              packets_received REAL,
              event_type TEXT DEFAULT 'stats'
            );
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_stats_ts ON stats_events(ts_ms);")

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS ml_state (
              key TEXT PRIMARY KEY,
              value_json TEXT NOT NULL
            );
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS zabbix_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              event_id TEXT UNIQUE,
              trigger_id TEXT,
              trigger_name TEXT,
              severity TEXT,
              hostname TEXT,
              status TEXT,
              description TEXT,
              clock_ms INTEGER,
              analysis TEXT
            );
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_zabbix_events_clock ON zabbix_events(clock_ms DESC);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_zabbix_events_severity ON zabbix_events(severity);")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS zabbix_user_cleared_event_ids (
              event_id TEXT PRIMARY KEY,
              cleared_at_ms INTEGER NOT NULL
            );
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS zabbix_metrics (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts_ms INTEGER NOT NULL,
              cpu_util REAL,
              ram_util REAL,
              net_in REAL
            );
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_zabbix_metrics_ts ON zabbix_metrics(ts_ms DESC);")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS zabbix_snapshots (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts_ms INTEGER NOT NULL,
              host_id TEXT,
              payload_json TEXT NOT NULL
            );
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_zabbix_snapshots_ts ON zabbix_snapshots(ts_ms DESC);")
        conn.commit()

    def insert_flow(self, log_data: Dict[str, Any]) -> Optional[int]:
        """
        Stores numeric ML features extracted from Suricata 'flow' events.
        """
        ts_ms = iso_to_ms(log_data.get("timestamp")) or utc_ms_now()
        f = log_data.get("flow") or log_data
        src_ip = safe_text(log_data.get("src_ip") or f.get("src_ip") or "0.0.0.0")
        dest_ip = safe_text(log_data.get("dest_ip") or f.get("dest_ip") or "0.0.0.0")
        proto = safe_text(log_data.get("proto") or f.get("proto") or "")
        src_port = parse_int(log_data.get("src_port") or f.get("src_port") or f.get("sport"), None)
        dest_port = parse_int(log_data.get("dest_port") or f.get("dest_port") or f.get("dport"), None)
        # Suricata field names vary slightly across versions/rulesets.
        # We accept multiple aliases to improve feature extraction robustness.
        bytes_toserver = parse_float(
            f.get("bytes_toserver") or f.get("bytes_to_server") or f.get("bytes_to_server") or None,
            None,
        )
        pkts_toserver = parse_float(
            f.get("pkts_toserver") or f.get("pkts_to_server") or f.get("pkts_to_server") or None,
            None,
        )
        # Suricata uses different names for duration depending on version/ruleset.
        # In our runtime evidence, flow samples include `age`, `start`, `end`.
        flow_duration = parse_float(
            f.get("flow_duration")
            or f.get("duration")
            or f.get("flow_duration_sec")
            or f.get("age"),
            None,
        )
        state = safe_text(f.get("state") or "")
        flow_key = compute_flow_key(
            src_ip=src_ip,
            src_port=src_port if src_port is not None else -1,
            dest_ip=dest_ip,
            dest_port=dest_port if dest_port is not None else -1,
            proto=proto,
        )

        # Only store when we have all required numeric features.
        missing: List[str] = []
        if bytes_toserver is None:
            missing.append("bytes_toserver")
        if pkts_toserver is None:
            missing.append("pkts_toserver")
        if dest_port is None:
            missing.append("dest_port")
        if flow_duration is None:
            missing.append("flow_duration/duration")
        if not proto:
            missing.append("proto")

        if missing:
            global _DEBUG3_FLOW_DEBUGGED
            if not _DEBUG3_FLOW_DEBUGGED:
                _DEBUG3_FLOW_DEBUGGED = True
                # #region agent log
                _debug3_log(
                    runId="pre",
                    hypothesisId="H_FLOW_FEATURES_MISSING",
                    location="soc_db.py:insert_flow",
                    message="Flow sample missing ML features",
                    data={
                        "missing": missing,
                        "src_ip": src_ip,
                        "dest_ip": dest_ip,
                        "proto": proto,
                        "src_port": src_port if src_port is not None else None,
                        "dest_port": dest_port if dest_port is not None else None,
                        "raw_flow_keys": list((log_data.get("flow") or log_data).keys())[:20],
                    },
                )
                # #endregion agent log
            return None

        conn = self.connect()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO flow_events (
              ts_ms, src_ip, dest_ip, src_port, dest_port, proto,
              bytes_toserver, pkts_toserver, flow_duration, state, flow_key,
              labeled_status, label_source, updated_at_ms
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'unlabeled', NULL, ?)
            """,
            (
                ts_ms,
                src_ip,
                dest_ip,
                src_port,
                dest_port,
                proto,
                bytes_toserver,
                pkts_toserver,
                flow_duration,
                state,
                flow_key,
                ts_ms,
            ),
        )
        conn.commit()
        return int(cur.lastrowid)

    def insert_alert(self, log_data: Dict[str, Any], *, analysis: Optional[Dict[str, Any]] = None) -> Optional[int]:
        ts_ms = iso_to_ms(log_data.get("timestamp")) or utc_ms_now()
        proto = safe_text(log_data.get("proto") or "")
        src_ip = safe_text(log_data.get("src_ip") or "0.0.0.0")
        dest_ip = safe_text(log_data.get("dest_ip") or "0.0.0.0")
        src_port = parse_int(log_data.get("src_port"), None)
        dest_port = parse_int(log_data.get("dest_port"), None)
        a = log_data.get("alert") or {}
        signature = safe_text(a.get("signature") or "")
        category = safe_text(a.get("category") or "")
        severity = safe_text(log_data.get("severity") or a.get("severity") or "")
        gid = parse_int(a.get("gid"), None)
        sid = parse_int(a.get("sid"), None)
        rev = parse_int(a.get("rev"), None)

        attack_type = (analysis or {}).get("attack_type")
        confidence = (analysis or {}).get("confidence")
        recommended_action = (analysis or {}).get("recommended_action")
        telegram_sent = 1 if (analysis or {}).get("telegram_sent") else 0

        conn = self.connect()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO alert_events (
              ts_ms, src_ip, dest_ip, src_port, dest_port, proto,
              signature, category, severity, gid, sid, rev,
              attack_type, confidence, recommended_action, telegram_sent
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ts_ms,
                src_ip,
                dest_ip,
                src_port,
                dest_port,
                proto,
                signature,
                category,
                severity,
                gid,
                sid,
                rev,
                attack_type,
                confidence,
                recommended_action,
                telegram_sent,
            ),
        )
        conn.commit()
        return int(cur.lastrowid)

    def label_flows_for_alert(
        self,
        *,
        alert_log_data: Dict[str, Any],
        match_window_sec: int = 120,
    ) -> int:
        """
        Marks the most recent flow sample matching the alert 5-tuple as 'malicious'.
        """
        ts_ms = iso_to_ms(alert_log_data.get("timestamp")) or utc_ms_now()
        src_ip = safe_text(alert_log_data.get("src_ip") or "0.0.0.0")
        dest_ip = safe_text(alert_log_data.get("dest_ip") or "0.0.0.0")
        src_port = parse_int(alert_log_data.get("src_port"), -1)
        dest_port = parse_int(alert_log_data.get("dest_port"), -1)
        proto = safe_text(alert_log_data.get("proto") or "")
        if not proto:
            return 0
        flow_key = compute_flow_key(
            src_ip=src_ip,
            src_port=src_port if src_port is not None else -1,
            dest_ip=dest_ip,
            dest_port=dest_port if dest_port is not None else -1,
            proto=proto,
        )

        conn = self.connect()
        cur = conn.cursor()
        win_ms = int(match_window_sec * 1000)
        cur.execute(
            """
            SELECT id, ts_ms
            FROM flow_events
            WHERE flow_key = ?
              AND ts_ms <= ?
              AND ts_ms >= ?
              AND labeled_status != 'malicious'
            ORDER BY ts_ms DESC
            LIMIT 1
            """,
            (flow_key, ts_ms, ts_ms - win_ms),
        )
        row = cur.fetchone()
        if not row:
            conn.commit()
            return 0

        cur.execute(
            """
            UPDATE flow_events
            SET labeled_status = 'malicious',
                label_source = 'alert',
                updated_at_ms = ?
            WHERE id = ?
            """,
            (ts_ms, int(row["id"])),
        )
        conn.commit()
        return 1

    def get_latest_flow_features(
        self,
        *,
        flow_key: str,
        alert_ts_ms: int,
        match_window_sec: int = 120,
    ) -> Optional[Dict[str, Any]]:
        """
        Fetches the most recent flow sample matching the alert flow_key within a time window.
        Used for ML inference for an alert.
        """
        conn = self.connect()
        cur = conn.cursor()
        win_ms = int(match_window_sec * 1000)
        cur.execute(
            """
            SELECT
              id, ts_ms, bytes_toserver, pkts_toserver, dest_port, proto, flow_duration
            FROM flow_events
            WHERE flow_key = ?
              AND ts_ms <= ?
              AND ts_ms >= ?
            ORDER BY ts_ms DESC
            LIMIT 1
            """,
            (flow_key, alert_ts_ms, alert_ts_ms - win_ms),
        )
        row = cur.fetchone()
        if not row:
            return None
        return {
            "id": int(row["id"]),
            "ts_ms": int(row["ts_ms"]),
            "bytes_toserver": float(row["bytes_toserver"]),
            "pkts_toserver": float(row["pkts_toserver"]),
            "dest_port": float(row["dest_port"]),
            "proto": row["proto"],
            "flow_duration": float(row["flow_duration"]),
        }

    def insert_dns(self, log_data: Dict[str, Any]) -> Optional[int]:
        ts_ms = iso_to_ms(log_data.get("timestamp")) or utc_ms_now()
        d = log_data.get("dns") or log_data
        src_ip = safe_text(log_data.get("src_ip") or d.get("src_ip") or "")
        query = safe_text(d.get("rrname") or d.get("query") or "")
        rrtype = safe_text(d.get("rrtype") or d.get("type") or "")
        rcode = safe_text(d.get("rcode") or d.get("response_code") or "")
        host = safe_text(d.get("hostname") or d.get("host") or "")
        if not query:
            return None
        conn = self.connect()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO dns_events(ts_ms, src_ip, query, rrtype, rcode, host)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            (ts_ms, src_ip, query, rrtype, rcode, host),
        )
        conn.commit()
        return int(cur.lastrowid)

    def insert_http(self, log_data: Dict[str, Any]) -> Optional[int]:
        ts_ms = iso_to_ms(log_data.get("timestamp")) or utc_ms_now()
        h = log_data.get("http") or log_data
        src_ip = safe_text(log_data.get("src_ip") or "")
        hostname = safe_text(h.get("hostname") or h.get("host") or "")
        method = safe_text(h.get("http_method") or h.get("method") or "")
        status = parse_int(h.get("status"), None)
        user_agent = safe_text(h.get("http_user_agent") or h.get("user_agent") or h.get("ua") or "")
        if not hostname and not status:
            return None
        conn = self.connect()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO http_events(ts_ms, src_ip, hostname, http_method, status, user_agent)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            (ts_ms, src_ip, hostname, method, status, user_agent),
        )
        conn.commit()
        return int(cur.lastrowid)

    def insert_tls(self, log_data: Dict[str, Any]) -> Optional[int]:
        ts_ms = iso_to_ms(log_data.get("timestamp")) or utc_ms_now()
        t = log_data.get("tls") or log_data
        src_ip = safe_text(log_data.get("src_ip") or "")
        sni = safe_text(t.get("sni") or t.get("server_name") or "")
        tls_version = safe_text(t.get("version") or t.get("tls_version") or "")
        if not sni and not tls_version:
            return None
        conn = self.connect()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO tls_events(ts_ms, src_ip, sni, tls_version)
            VALUES(?, ?, ?, ?)
            """,
            (ts_ms, src_ip, sni, tls_version),
        )
        conn.commit()
        return int(cur.lastrowid)

    def insert_fileinfo(self, log_data: Dict[str, Any]) -> Optional[int]:
        ts_ms = iso_to_ms(log_data.get("timestamp")) or utc_ms_now()
        fi = log_data.get("fileinfo") or log_data
        src_ip = safe_text(log_data.get("src_ip") or "")
        filename = safe_text(fi.get("filename") or fi.get("file_name") or "")
        mime_type = safe_text(fi.get("mime_type") or fi.get("mime") or "")
        size_bytes = parse_int(fi.get("size") or fi.get("size_bytes"), None)
        source = safe_text(fi.get("source") or fi.get("file_source") or "")
        if not filename and not mime_type and size_bytes is None:
            return None
        conn = self.connect()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO fileinfo_events(ts_ms, src_ip, filename, mime_type, size_bytes, source)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            (ts_ms, src_ip, filename, mime_type, size_bytes, source),
        )
        conn.commit()
        return int(cur.lastrowid)

    def insert_stats(self, log_data: Dict[str, Any]) -> Optional[int]:
        ts_ms = iso_to_ms(log_data.get("timestamp")) or utc_ms_now()
        s = log_data.get("stats") or log_data
        packet_drops = parse_float(s.get("packet_drops") or s.get("packet_drop") or s.get("drops"), None)
        packets_received = parse_float(s.get("packets_received") or s.get("packets") or s.get("received"), None)
        if packet_drops is None and packets_received is None:
            return None
        conn = self.connect()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO stats_events(ts_ms, packet_drops, packets_received)
            VALUES(?, ?, ?)
            """,
            (ts_ms, packet_drops, packets_received),
        )
        conn.commit()
        return int(cur.lastrowid)

    def update_ml_state(self, *, key: str, value: Dict[str, Any]) -> None:
        conn = self.connect()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO ml_state(key, value_json)
            VALUES(?, ?)
            ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json
            """,
            (key, json.dumps(value, ensure_ascii=False)),
        )
        conn.commit()

    def get_ml_state(self, *, key: str) -> Optional[Dict[str, Any]]:
        conn = self.connect()
        cur = conn.cursor()
        cur.execute("SELECT value_json FROM ml_state WHERE key = ? LIMIT 1", (key,))
        row = cur.fetchone()
        if not row:
            return None
        try:
            return json.loads(row["value_json"])
        except Exception:
            return None

    def _bucket_expr(self, ts_ms_col: str, window_minutes: int, bucket_minutes: int) -> str:
        # We use integer division to bucket by minutes.
        # floor((ts_ms - start)/bucket) to align relative to the window start.
        # In SQL we approximate with CURRENT timestamp since this is DB-local.
        # Simpler: use timestamp/ bucket directly. For dashboard this is enough.
        return f"(CAST({ts_ms_col} / 60000 / {bucket_minutes} AS INTEGER) * {bucket_minutes})"

    def analytics_dashboard(self, *, window_minutes: int = 60, bucket_minutes: int = 5, max_items: int = 8) -> Dict[str, Any]:
        """
        Returns pre-aggregated datasets suitable for Chart.js.
        """
        conn = self.connect()
        cur = conn.cursor()
        window_ms = int(window_minutes * 60 * 1000)
        end_ms = utc_ms_now()
        start_ms = end_ms - window_ms

        # Network visibility (flow events)
        cur.execute(
            """
            SELECT
              src_ip,
              SUM(bytes_toserver) AS bytes_sum
            FROM flow_events
            WHERE ts_ms BETWEEN ? AND ?
            GROUP BY src_ip
            ORDER BY bytes_sum DESC
            LIMIT ?
            """,
            (start_ms, end_ms, max_items),
        )
        top_talkers = [{"label": r["src_ip"], "value": float(r["bytes_sum"] or 0)} for r in cur.fetchall()]

        cur.execute(
            """
            SELECT
              proto,
              COUNT(*) AS cnt
            FROM flow_events
            WHERE ts_ms BETWEEN ? AND ?
            GROUP BY proto
            ORDER BY cnt DESC
            """,
            (start_ms, end_ms),
        )
        protocol_distribution = [{"label": r["proto"], "value": int(r["cnt"])} for r in cur.fetchall()]

        cur.execute(
            """
            SELECT
              state,
              COUNT(*) AS cnt
            FROM flow_events
            WHERE ts_ms BETWEEN ? AND ?
            GROUP BY state
            ORDER BY cnt DESC
            LIMIT ?
            """,
            (start_ms, end_ms, max_items),
        )
        flow_states = [{"label": r["state"] or "unknown", "value": int(r["cnt"])} for r in cur.fetchall()]

        # bytes line chart
        cur.execute(
            """
            SELECT
              (CAST(ts_ms / 60000 / ? AS INTEGER) * ?) AS bucket_key,
              SUM(bytes_toserver) AS bytes_sum
            FROM flow_events
            WHERE ts_ms BETWEEN ? AND ?
            GROUP BY bucket_key
            ORDER BY bucket_key ASC
            """,
            (bucket_minutes, bucket_minutes, start_ms, end_ms),
        )
        buckets = cur.fetchall()
        total_bytes_line = {
            "labels": [str(int(b["bucket_key"] or 0)) for b in buckets],
            "values": [float(b["bytes_sum"] or 0) for b in buckets],
        }

        # Web & Apps (HTTP + TLS)
        cur.execute(
            """
            SELECT hostname, COUNT(*) AS cnt
            FROM http_events
            WHERE ts_ms BETWEEN ? AND ?
              AND hostname IS NOT NULL AND hostname != ''
            GROUP BY hostname
            ORDER BY cnt DESC
            LIMIT ?
            """,
            (start_ms, end_ms, max_items),
        )
        hostnames = [{"label": r["hostname"], "value": int(r["cnt"])} for r in cur.fetchall()]

        cur.execute(
            """
            SELECT status, COUNT(*) AS cnt
            FROM http_events
            WHERE ts_ms BETWEEN ? AND ?
            GROUP BY status
            ORDER BY cnt DESC
            LIMIT ?
            """,
            (start_ms, end_ms, max_items),
        )
        http_status_codes = [{"label": str(r["status"]), "value": int(r["cnt"])} for r in cur.fetchall() if r["status"] is not None]

        cur.execute(
            """
            SELECT user_agent, COUNT(*) AS cnt
            FROM http_events
            WHERE ts_ms BETWEEN ? AND ?
              AND user_agent IS NOT NULL AND user_agent != ''
            GROUP BY user_agent
            ORDER BY cnt DESC
            LIMIT ?
            """,
            (start_ms, end_ms, max_items),
        )
        user_agents = [{"label": r["user_agent"], "value": int(r["cnt"])} for r in cur.fetchall()]

        cur.execute(
            """
            SELECT tls_version, COUNT(*) AS cnt
            FROM tls_events
            WHERE ts_ms BETWEEN ? AND ?
            GROUP BY tls_version
            ORDER BY cnt DESC
            LIMIT ?
            """,
            (start_ms, end_ms, max_items),
        )
        tls_versions = [{"label": r["tls_version"] or "unknown", "value": int(r["cnt"])} for r in cur.fetchall()]

        # DNS
        cur.execute(
            """
            SELECT query, COUNT(*) AS cnt
            FROM dns_events
            WHERE ts_ms BETWEEN ? AND ?
              AND query IS NOT NULL AND query != ''
            GROUP BY query
            ORDER BY cnt DESC
            LIMIT ?
            """,
            (start_ms, end_ms, max_items),
        )
        top_queries = [{"label": r["query"], "value": int(r["cnt"])} for r in cur.fetchall()]

        cur.execute(
            """
            SELECT rcode, COUNT(*) AS cnt
            FROM dns_events
            WHERE ts_ms BETWEEN ? AND ?
            GROUP BY rcode
            ORDER BY cnt DESC
            LIMIT ?
            """,
            (start_ms, end_ms, max_items),
        )
        response_codes = [{"label": str(r["rcode"]), "value": int(r["cnt"])} for r in cur.fetchall()]

        # NXDOMAIN tracking (Suricata rcode often uses string or numeric "NXDOMAIN" / 3)
        cur.execute(
            """
            SELECT
              SUM(CASE
                    WHEN rcode IN ('NXDOMAIN', 'nxdomain', '3') THEN 1
                    WHEN rcode = '0' THEN 0
                    ELSE CASE WHEN rcode LIKE '%NX%' THEN 1 ELSE 0 END
                  END) AS nxd_cnt,
              COUNT(*) AS total_cnt
            FROM dns_events
            WHERE ts_ms BETWEEN ? AND ?
            """,
            (start_ms, end_ms),
        )
        row = cur.fetchone()
        nxdomain_rate = float((row["nxd_cnt"] or 0) / max(1, (row["total_cnt"] or 0)))

        cur.execute(
            """
            SELECT rrtype, COUNT(*) AS cnt
            FROM dns_events
            WHERE ts_ms BETWEEN ? AND ?
            GROUP BY rrtype
            ORDER BY cnt DESC
            LIMIT ?
            """,
            (start_ms, end_ms, max_items),
        )
        record_types = [{"label": r["rrtype"] or "unknown", "value": int(r["cnt"])} for r in cur.fetchall()]

        # File Info
        cur.execute(
            """
            SELECT mime_type, COUNT(*) AS cnt
            FROM fileinfo_events
            WHERE ts_ms BETWEEN ? AND ?
            GROUP BY mime_type
            ORDER BY cnt DESC
            LIMIT ?
            """,
            (start_ms, end_ms, max_items),
        )
        mime_types = [{"label": r["mime_type"] or "unknown", "value": int(r["cnt"])} for r in cur.fetchall()]

        # file size histogram (basic bins)
        cur.execute(
            """
            SELECT
              CASE
                WHEN size_bytes IS NULL THEN 'unknown'
                WHEN size_bytes < 1*1024 THEN '<1KB'
                WHEN size_bytes < 10*1024 THEN '1-10KB'
                WHEN size_bytes < 100*1024 THEN '10-100KB'
                WHEN size_bytes < 1*1024*1024 THEN '100KB-1MB'
                ELSE '>1MB'
              END AS bin,
              COUNT(*) AS cnt
            FROM fileinfo_events
            WHERE ts_ms BETWEEN ? AND ?
            GROUP BY bin
            ORDER BY cnt DESC
            LIMIT ?
            """,
            (start_ms, end_ms, max_items),
        )
        file_sizes = [{"label": r["bin"], "value": int(r["cnt"])} for r in cur.fetchall()]

        cur.execute(
            """
            SELECT source, COUNT(*) AS cnt
            FROM fileinfo_events
            WHERE ts_ms BETWEEN ? AND ?
            GROUP BY source
            ORDER BY cnt DESC
            LIMIT ?
            """,
            (start_ms, end_ms, max_items),
        )
        top_file_sources = [{"label": r["source"] or "unknown", "value": int(r["cnt"])} for r in cur.fetchall()]

        # Alerts
        cur.execute(
            """
            SELECT severity, COUNT(*) AS cnt
            FROM alert_events
            WHERE ts_ms BETWEEN ? AND ?
            GROUP BY severity
            ORDER BY cnt DESC
            """,
            (start_ms, end_ms),
        )
        severity_distribution = [{"label": r["severity"] or "Medium", "value": int(r["cnt"])} for r in cur.fetchall()]

        # Top SID: we prefer sid (numeric), else signature
        cur.execute(
            """
            SELECT
              COALESCE(CAST(sid AS TEXT), signature) AS sid_label,
              COUNT(*) AS cnt
            FROM alert_events
            WHERE ts_ms BETWEEN ? AND ?
            GROUP BY sid_label
            ORDER BY cnt DESC
            LIMIT ?
            """,
            (start_ms, end_ms, max_items),
        )
        top_sid = [{"label": r["sid_label"] or "unknown", "value": int(r["cnt"])} for r in cur.fetchall()]

        # Attack timeline: alert counts by bucket
        cur.execute(
            """
            SELECT
              (CAST(ts_ms / 60000 / ? AS INTEGER) * ?) AS bucket_key,
              COUNT(*) AS cnt
            FROM alert_events
            WHERE ts_ms BETWEEN ? AND ?
            GROUP BY bucket_key
            ORDER BY bucket_key ASC
            """,
            (bucket_minutes, bucket_minutes, start_ms, end_ms),
        )
        buckets = cur.fetchall()
        attack_timeline = {
            "labels": [str(int(b["bucket_key"] or 0)) for b in buckets],
            "values": [int(b["cnt"] or 0) for b in buckets],
        }

        # Subnet heatmap (src /24) - aggregate in Python to avoid SQLite INSTR arity issues.
        cur.execute(
            """
            SELECT
              src_ip,
              COUNT(*) AS cnt
            FROM alert_events
            WHERE ts_ms BETWEEN ? AND ?
            GROUP BY src_ip
            ORDER BY cnt DESC
            """,
            (start_ms, end_ms),
        )
        subnet_counts: Dict[str, int] = {}
        for r in cur.fetchall():
            ip = (r["src_ip"] or "").strip()
            cnt = int(r["cnt"] or 0)
            if ip.count(".") >= 3:
                parts = ip.split(".")
                subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            elif ip:
                subnet = ip  # keep IPv6/unknown format as-is
            else:
                subnet = "unknown"
            subnet_counts[subnet] = subnet_counts.get(subnet, 0) + cnt
        subnet_heatmap = [
            {"label": k, "value": v}
            for k, v in sorted(subnet_counts.items(), key=lambda x: x[1], reverse=True)[:max_items]
        ]

        # System health
        cur.execute(
            """
            SELECT
              (CAST(ts_ms / 60000 / ? AS INTEGER) * ?) AS bucket_key,
              AVG(packet_drops) AS avg_drops,
              AVG(packets_received) AS avg_received
            FROM stats_events
            WHERE ts_ms BETWEEN ? AND ?
            GROUP BY bucket_key
            ORDER BY bucket_key ASC
            """,
            (bucket_minutes, bucket_minutes, start_ms, end_ms),
        )
        buckets = cur.fetchall()
        # packet_drop_rate = avg_drops / avg_received
        packet_drop_rate = {
            "labels": [str(int(b["bucket_key"] or 0)) for b in buckets],
            "values": [float((b["avg_drops"] or 0) / max(1e-9, (b["avg_received"] or 1))) for b in buckets],
        }

        # Event type breakdown: count flow/alert/dns in window
        cur.execute(
            """
            SELECT 'flow' AS event_type, COUNT(*) AS cnt
            FROM flow_events
            WHERE ts_ms BETWEEN ? AND ?
            UNION ALL
            SELECT 'alert' AS event_type, COUNT(*) AS cnt
            FROM alert_events
            WHERE ts_ms BETWEEN ? AND ?
            UNION ALL
            SELECT 'dns' AS event_type, COUNT(*) AS cnt
            FROM dns_events
            WHERE ts_ms BETWEEN ? AND ?
            """,
            (start_ms, end_ms, start_ms, end_ms, start_ms, end_ms),
        )
        event_type_breakdown = [{"label": r["event_type"], "value": int(r["cnt"])} for r in cur.fetchall()]

        return {
            "meta": {
                "window_minutes": window_minutes,
                "bucket_minutes": bucket_minutes,
                "start_ms": start_ms,
                "end_ms": end_ms,
            },
            "network_visibility": {
                "total_bytes_line": total_bytes_line,
                "protocol_distribution": protocol_distribution,
                "top_talkers": top_talkers,
                "flow_states": flow_states,
            },
            "web_apps": {
                "hostnames": hostnames,
                "http_status_codes": http_status_codes,
                "user_agents": user_agents,
                "tls_versions": tls_versions,
            },
            "dns": {
                "top_queries": top_queries,
                "response_codes": response_codes,
                "nxdomain_rate": nxdomain_rate,
                "record_types": record_types,
            },
            "file_info": {
                "mime_types": mime_types,
                "file_sizes": file_sizes,
                "top_file_sources": top_file_sources,
            },
            "alerts": {
                "severity_distribution": severity_distribution,
                "top_sid": top_sid,
                "attack_timeline": attack_timeline,
                "subnet_heatmap": subnet_heatmap,
            },
            "system_health": {
                "packet_drop_rate": packet_drop_rate,
                "event_type_breakdown": event_type_breakdown,
            },
        }

    def get_recent_ids_alerts(self, *, limit: int = 200) -> List[Dict[str, Any]]:
        """
        Returns latest Suricata IDS alert events (already enriched with AI fields if present).
        """
        conn = self.connect()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT
              ts_ms, src_ip, dest_ip, src_port, dest_port, proto,
              signature, category, severity, gid, sid, rev,
              attack_type, confidence, recommended_action
            FROM alert_events
            ORDER BY ts_ms DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cur.fetchall()
        out: List[Dict[str, Any]] = []
        for r in rows:
            out.append(
                {
                    "timestamp": ts_ms_to_vn_iso(r["ts_ms"]),
                    "ts_ms": int(r["ts_ms"] or 0),
                    "src_ip": r["src_ip"] or "",
                    "dest_ip": r["dest_ip"] or "",
                    "src_port": int(r["src_port"] or 0) if r["src_port"] is not None else None,
                    "dest_port": int(r["dest_port"] or 0) if r["dest_port"] is not None else None,
                    "proto": r["proto"] or "",
                    "signature": r["signature"] or "",
                    "category": r["category"] or "",
                    "severity": r["severity"] or "Medium",
                    "gid": int(r["gid"] or 0) if r["gid"] is not None else None,
                    "sid": int(r["sid"] or 0) if r["sid"] is not None else None,
                    "rev": int(r["rev"] or 0) if r["rev"] is not None else None,
                    "attack_type": r["attack_type"] or "",
                    "confidence": r["confidence"] or "",
                    "recommended_action": r["recommended_action"] or "",
                }
            )
        return out

    def insert_zabbix_event(self, event: Dict[str, Any]) -> Optional[int]:
        conn = self.connect()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT OR IGNORE INTO zabbix_events(
              event_id, trigger_id, trigger_name, severity, hostname, status, description, clock_ms, analysis
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.get("event_id"),
                event.get("trigger_id"),
                event.get("trigger_name"),
                event.get("severity"),
                event.get("hostname"),
                event.get("status"),
                event.get("description"),
                event.get("clock_ms"),
                event.get("analysis"),
            ),
        )
        conn.commit()
        return int(cur.lastrowid or 0)

    def get_zabbix_event_analysis(self, event_id: str) -> Optional[str]:
        conn = self.connect()
        cur = conn.cursor()
        cur.execute("SELECT analysis FROM zabbix_events WHERE event_id = ? LIMIT 1", (event_id,))
        row = cur.fetchone()
        if not row:
            return None
        v = row["analysis"] if isinstance(row, sqlite3.Row) else row[0]
        return str(v) if v else None

    def upsert_zabbix_event(self, event: Dict[str, Any]) -> None:
        conn = self.connect()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO zabbix_events(
              event_id, trigger_id, trigger_name, severity, hostname, status, description, clock_ms, analysis
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(event_id) DO UPDATE SET
              trigger_id = excluded.trigger_id,
              trigger_name = excluded.trigger_name,
              severity = excluded.severity,
              hostname = excluded.hostname,
              status = excluded.status,
              description = excluded.description,
              clock_ms = excluded.clock_ms,
              analysis = COALESCE(zabbix_events.analysis, excluded.analysis)
            """,
            (
                event.get("event_id"),
                event.get("trigger_id"),
                event.get("trigger_name"),
                event.get("severity"),
                event.get("hostname"),
                event.get("status"),
                event.get("description"),
                event.get("clock_ms"),
                event.get("analysis"),
            ),
        )
        conn.commit()

    def insert_zabbix_snapshot(self, *, host_id: Optional[str], payload: Dict[str, Any]) -> Optional[int]:
        conn = self.connect()
        cur = conn.cursor()
        ts_ms = utc_ms_now()
        cur.execute(
            """
            INSERT INTO zabbix_snapshots(ts_ms, host_id, payload_json)
            VALUES(?, ?, ?)
            """,
            (ts_ms, host_id or "", json.dumps(payload, ensure_ascii=False)),
        )
        conn.commit()
        return int(cur.lastrowid or 0)

    def insert_metric_point(self, *, cpu: Optional[float], ram: Optional[float], net_in: Optional[float]) -> Optional[int]:
        conn = self.connect()
        cur = conn.cursor()
        ts_ms = utc_ms_now()
        cur.execute(
            """
            INSERT INTO zabbix_metrics(ts_ms, cpu_util, ram_util, net_in)
            VALUES(?, ?, ?, ?)
            """,
            (ts_ms, cpu, ram, net_in),
        )
        conn.commit()
        return int(cur.lastrowid)

    def get_recent_zabbix_events(self, *, limit: int = 200) -> List[Dict[str, Any]]:
        conn = self.connect()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT event_id, trigger_id, trigger_name, severity, hostname, status, description, clock_ms, analysis
            FROM zabbix_events
            ORDER BY clock_ms DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cur.fetchall()
        out: List[Dict[str, Any]] = []
        for r in rows:
            out.append(
                {
                    "event_id": r["event_id"],
                    "trigger_id": r["trigger_id"],
                    "trigger_name": r["trigger_name"],
                    "severity": r["severity"],
                    "hostname": r["hostname"],
                    "status": r["status"],
                    "description": r["description"],
                    "clock_ms": int(r["clock_ms"] or 0),
                    "analysis": r["analysis"] or "",
                    "timestamp": ts_ms_to_vn_iso(r["clock_ms"]),
                }
            )
        return out

    def get_kpis(self) -> Dict[str, Any]:
        conn = self.connect()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(1) FROM zabbix_events")
        total = int(cur.fetchone()[0] or 0)
        cur.execute("SELECT COUNT(1) FROM zabbix_events WHERE severity IN ('High','Disaster')")
        critical = int(cur.fetchone()[0] or 0)
        cur.execute("SELECT COUNT(1) FROM zabbix_events WHERE status='PROBLEM'")
        open_problems = int(cur.fetchone()[0] or 0)
        cur.execute(
            """
            SELECT COUNT(1) FROM zabbix_events
            WHERE status='PROBLEM' AND severity IN ('Warning','Average','High','Disaster')
            """
        )
        active_severity_alerts = int(cur.fetchone()[0] or 0)
        latest = self.get_latest_zabbix_snapshot()
        payload = (latest or {}).get("payload") or {}
        metrics = payload.get("metrics") or {}
        return {
            "total_alerts": total,
            "critical_threats": critical,
            "system_status": "HEALTHY" if open_problems == 0 else "DEGRADED",
            "open_problems": open_problems,
            "active_severity_alerts": active_severity_alerts,
            "uptime_sec": metrics.get("system.uptime"),
            "logged_in_users": metrics.get("system.users.num"),
            "network_status": payload.get("network_status")
            or ("UP" if metrics.get('net.if.in["zttqhuceey"]') is not None else "UNKNOWN"),
        }

    def get_top_rule_violations(self, *, limit: int = 5) -> List[Dict[str, Any]]:
        conn = self.connect()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT trigger_name, COUNT(1) AS cnt
            FROM zabbix_events
            GROUP BY trigger_name
            ORDER BY cnt DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [{"rule": r["trigger_name"], "count": int(r["cnt"] or 0)} for r in cur.fetchall()]

    def get_latest_zabbix_snapshot(self) -> Optional[Dict[str, Any]]:
        conn = self.connect()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT ts_ms, host_id, payload_json
            FROM zabbix_snapshots
            ORDER BY ts_ms DESC
            LIMIT 1
            """
        )
        row = cur.fetchone()
        if not row:
            return None
        try:
            payload = json.loads(row["payload_json"] or "{}")
        except Exception:
            payload = {}
        return {"ts_ms": int(row["ts_ms"] or 0), "host_id": row["host_id"] or "", "payload": payload}

    def get_zabbix_snapshot_series(self, *, hours: int = 24) -> List[Dict[str, Any]]:
        end_ms = utc_ms_now()
        start_ms = end_ms - hours * 3600 * 1000
        conn = self.connect()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT ts_ms, host_id, payload_json
            FROM zabbix_snapshots
            WHERE ts_ms BETWEEN ? AND ?
            ORDER BY ts_ms ASC
            """,
            (start_ms, end_ms),
        )
        out: List[Dict[str, Any]] = []
        for r in cur.fetchall():
            try:
                payload = json.loads(r["payload_json"] or "{}")
            except Exception:
                payload = {}
            out.append(
                {
                    "ts_ms": int(r["ts_ms"] or 0),
                    "host_id": r["host_id"] or "",
                    "payload": payload,
                }
            )
        return out

    def zabbix_severity_distribution(self) -> Dict[str, int]:
        conn = self.connect()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT severity, COUNT(1) AS cnt
            FROM zabbix_events
            WHERE severity IS NOT NULL AND severity != ''
            GROUP BY severity
            """
        )
        return {str(r["severity"] or ""): int(r["cnt"] or 0) for r in cur.fetchall()}

    def get_metrics_series(self, *, minutes: int = 60) -> Dict[str, Any]:
        end_ms = utc_ms_now()
        start_ms = end_ms - minutes * 60 * 1000
        conn = self.connect()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT ts_ms, payload_json
            FROM zabbix_snapshots
            WHERE ts_ms BETWEEN ? AND ?
            ORDER BY ts_ms ASC
            """,
            (start_ms, end_ms),
        )
        snap_rows = cur.fetchall()
        if snap_rows:
            labels = [
                datetime.fromtimestamp((r["ts_ms"] or 0) / 1000, tz=VN_TZ).strftime("%H:%M:%S")
                for r in snap_rows
            ]
            cpu: List[float] = []
            ram: List[float] = []
            net: List[float] = []
            for r in snap_rows:
                try:
                    payload = json.loads(r["payload_json"] or "{}")
                except Exception:
                    payload = {}
                m = payload.get("metrics") or {}
                cpu.append(float(m.get("system.cpu.util") or 0))
                ram.append(float(m.get("vm.memory.utilization") or 0))
                net.append(float(m.get('net.if.in["zttqhuceey"]') or 0))
            return {"labels": labels, "cpu": cpu, "ram": ram, "net": net}

        cur.execute(
            """
            SELECT ts_ms, cpu_util, ram_util, net_in
            FROM zabbix_metrics
            WHERE ts_ms BETWEEN ? AND ?
            ORDER BY ts_ms ASC
            """,
            (start_ms, end_ms),
        )
        rows = cur.fetchall()
        labels = [datetime.fromtimestamp((r["ts_ms"] or 0) / 1000, tz=VN_TZ).strftime("%H:%M:%S") for r in rows]
        return {
            "labels": labels,
            "cpu": [float(r["cpu_util"] or 0) for r in rows],
            "ram": [float(r["ram_util"] or 0) for r in rows],
            "net": [float(r["net_in"] or 0) for r in rows],
        }

    def get_history_events(self, *, limit: int = 500, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = self.connect()
        cur = conn.cursor()
        if severity:
            cur.execute(
                """
                SELECT event_id, trigger_id, trigger_name, severity, hostname, status, description, clock_ms, analysis
                FROM zabbix_events
                WHERE severity = ?
                ORDER BY clock_ms DESC
                LIMIT ?
                """,
                (severity, limit),
            )
        else:
            cur.execute(
                """
                SELECT event_id, trigger_id, trigger_name, severity, hostname, status, description, clock_ms, analysis
                FROM zabbix_events
                ORDER BY clock_ms DESC
                LIMIT ?
                """,
                (limit,),
            )
        rows = cur.fetchall()
        return [
            {
                "event_id": r["event_id"],
                "trigger_id": r["trigger_id"],
                "trigger_name": r["trigger_name"],
                "severity": r["severity"],
                "hostname": r["hostname"],
                "status": r["status"],
                "description": r["description"],
                "clock_ms": int(r["clock_ms"] or 0),
                "analysis": r["analysis"] or "",
                "timestamp": ts_ms_to_vn_iso(r["clock_ms"]),
            }
            for r in rows
        ]

    def is_zabbix_event_user_cleared(self, event_id: str) -> bool:
        if not event_id:
            return False
        conn = self.connect()
        cur = conn.cursor()
        cur.execute(
            "SELECT 1 FROM zabbix_user_cleared_event_ids WHERE event_id = ? LIMIT 1",
            (str(event_id),),
        )
        return cur.fetchone() is not None

    def delete_all_zabbix_events(self) -> int:
        """
        Clear UI/event log: remember every current event_id so the Zabbix collector
        does not re-insert the same Zabbix problems on the next poll.
        """
        conn = self.connect()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(1) FROM zabbix_events")
        n = int(cur.fetchone()[0] or 0)
        now_ms = utc_ms_now()
        cur.execute(
            """
            INSERT OR IGNORE INTO zabbix_user_cleared_event_ids(event_id, cleared_at_ms)
            SELECT event_id, ? FROM zabbix_events WHERE event_id IS NOT NULL AND event_id != ''
            """,
            (now_ms,),
        )
        cur.execute("DELETE FROM zabbix_events")
        conn.commit()
        return n

    def delete_all_alert_events(self) -> int:
        conn = self.connect()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(1) FROM alert_events")
        n = int(cur.fetchone()[0] or 0)
        cur.execute("DELETE FROM alert_events")
        conn.commit()
        return n

