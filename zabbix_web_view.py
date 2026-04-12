import json
import os
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from flask import Flask, Response, jsonify, request


app = Flask(__name__)

ZABBIX_API_URL = os.environ.get("ZABBIX_API_URL", "http://172.25.0.20/zabbix/api_jsonrpc.php")
ZABBIX_USERNAME = os.environ.get("ZABBIX_USERNAME", "Admin")
ZABBIX_PASSWORD = os.environ.get("ZABBIX_PASSWORD", "zabbix")
ZABBIX_HOST_NAME = os.environ.get("ZABBIX_HOST_NAME", "Linux Server")
APP_HOST = os.environ.get("APP_HOST", "0.0.0.0")
APP_PORT = int(os.environ.get("APP_PORT", "5001"))
REQ_TIMEOUT = int(os.environ.get("REQ_TIMEOUT", "20"))

# #region agent log
DEBUG_LOG_PATH = Path(__file__).resolve().parent / "debug-f300aa.log"
DEBUG_SESSION = "f300aa"


def _debug_log(*, run_id: str, hypothesis_id: str, location: str, message: str, data: Dict[str, Any]) -> None:
    payload = {
        "sessionId": DEBUG_SESSION,
        "runId": run_id,
        "hypothesisId": hypothesis_id,
        "location": location,
        "message": message,
        "data": data,
        "timestamp": int(time.time() * 1000),
    }
    try:
        DEBUG_LOG_PATH.open("a", encoding="utf-8").write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        pass


# #endregion agent log


# #region agent log
_DEBUG396_PATH = Path(__file__).resolve().parent / "debug-39600c.log"


def _debug396_log(
    *,
    run_id: str,
    hypothesis_id: str,
    location: str,
    message: str,
    data: Dict[str, Any],
) -> None:
    payload = {
        "sessionId": "39600c",
        "runId": run_id,
        "hypothesisId": hypothesis_id,
        "location": location,
        "message": message,
        "data": data,
        "timestamp": int(time.time() * 1000),
    }
    try:
        _DEBUG396_PATH.open("a", encoding="utf-8").write(json.dumps(payload, ensure_ascii=False) + "\n")
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


class Zbx:
    def __init__(self) -> None:
        self.token: Optional[str] = None
        self.req_id = 1
        self.auth_mode = "json_auth"  # json_auth | bearer_header

    def rpc(self, method: str, params: Dict[str, Any], auth: bool = True) -> Any:
        def _post(*, use_payload_auth: bool, use_bearer: bool) -> Any:
            payload: Dict[str, Any] = {
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
                "id": self.req_id,
            }
            headers = {"Content-Type": "application/json-rpc"}
            if auth and use_payload_auth and self.token:
                payload["auth"] = self.token
            if auth and use_bearer and self.token:
                headers["Authorization"] = f"Bearer {self.token}"

            r = requests.post(ZABBIX_API_URL, json=payload, headers=headers, timeout=REQ_TIMEOUT)
            r.raise_for_status()
            body = r.json()
            if "error" in body:
                raise RuntimeError(str(body["error"]))
            return body.get("result")

        self.req_id += 1
        if not auth:
            return _post(use_payload_auth=False, use_bearer=False)

        if self.auth_mode == "json_auth":
            try:
                return _post(use_payload_auth=True, use_bearer=False)
            except RuntimeError as exc:
                msg = str(exc).lower()
                if 'unexpected parameter "auth"' in msg:
                    self.auth_mode = "bearer_header"
                    # #region agent log
                    _debug_log(
                        run_id="zbx-view",
                        hypothesis_id="H5_AUTH_MODE",
                        location="zabbix_web_view.py:rpc",
                        message="Switching auth mode to bearer_header",
                        data={"method": method},
                    )
                    # #endregion agent log
                    return _post(use_payload_auth=False, use_bearer=True)
                raise

        return _post(use_payload_auth=False, use_bearer=True)

    def login(self) -> str:
        if self.token:
            return self.token
        try:
            res = self.rpc(
                "user.login",
                {"username": ZABBIX_USERNAME, "password": ZABBIX_PASSWORD},
                auth=False,
            )
        except RuntimeError:
            res = self.rpc(
                "user.login",
                {"user": ZABBIX_USERNAME, "password": ZABBIX_PASSWORD},
                auth=False,
            )
        self.token = str(res)
        # #region agent log
        _debug_log(
            run_id="zbx-view",
            hypothesis_id="H1_API_REACHABLE",
            location="zabbix_web_view.py:login",
            message="Login success",
            data={"token_present": bool(self.token), "auth_mode": self.auth_mode},
        )
        # #endregion agent log
        return self.token

    def host_id(self, host_name: str) -> Optional[str]:
        self.login()
        rows = self.rpc(
            "host.get",
            {"output": ["hostid", "name", "host"], "search": {"name": host_name}},
            auth=True,
        )
        if not rows:
            return None
        return str(rows[0].get("hostid"))

    def items(self, host_id: str, keys: List[str]) -> List[Dict[str, Any]]:
        self.login()
        return self.rpc(
            "item.get",
            {
                "output": ["itemid", "name", "key_", "lastvalue", "units", "lastclock", "value_type"],
                "hostids": [host_id],
                "monitored": True,
                "filter": {"key_": keys},
            },
            auth=True,
        )


KEYS = [
    "system.cpu.util",
    "system.cpu.load[all,avg1]",
    "system.cpu.load[all,avg5]",
    "system.cpu.load[all,avg15]",
    "vm.memory.utilization",
    "vm.memory.size[available]",
    "system.swap.size[,pfree]",
    "vfs.fs.dependent.size[/,pused]",   
    "vfs.fs.dependent.inode[/,pfree]",  
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
]


def _fmt_uptime(seconds: Any) -> str:
    try:
        s = int(float(seconds))
    except Exception:
        return "N/A"
    d = s // 86400
    h = (s % 86400) // 3600
    m = (s % 3600) // 60
    return f"{d}d {h}h {m}m"


def _normalize(items: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for i in items:
        k = str(i.get("key_") or "")
        if not k:
            continue
        out[k] = i
    return out


def _metric(m: Dict[str, Dict[str, Any]], key: str) -> str:
    row = m.get(key) or {}
    v = row.get("lastvalue")
    u = row.get("units") or ""
    if v is None or str(v) == "":
        return "N/A"
    return f"{v}{u}"


def _build_payload() -> Dict[str, Any]:
    z = Zbx()
    # #region agent log
    _debug_log(
        run_id="zbx-view",
        hypothesis_id="H1_API_REACHABLE",
        location="zabbix_web_view.py:_build_payload",
        message="Start collecting metrics",
        data={"api_url": ZABBIX_API_URL, "host": ZABBIX_HOST_NAME},
    )
    # #endregion agent log

    z.login()
    hid = z.host_id(ZABBIX_HOST_NAME)
    if not hid:
        raise RuntimeError(f"Host not found: {ZABBIX_HOST_NAME}")
    rows = z.items(hid, KEYS)
    mm = _normalize(rows)
    # #region agent log
    _debug_log(
        run_id="zbx-view",
        hypothesis_id="H2_HOST_ITEMS",
        location="zabbix_web_view.py:_build_payload",
        message="Fetched host items",
        data={"hostid": hid, "returned": len(rows), "expected_keys": len(KEYS)},
    )
    # #endregion agent log

    tz_hcm = timezone(timedelta(hours=7))
    current_time_vn = datetime.now(tz_hcm).strftime("%Y-%m-%d %H:%M:%S") + " (UTC+7)"
    _debug89_log(
        run_id="zabbix-web-view",
        hypothesis_id="H1_TZ_VN",
        location="zabbix_web_view.py:_build_payload",
        message="Computed VN timestamp for payload",
        data={"timestamp": current_time_vn},
    )
    _debug89_log(
        run_id="zabbix-web-view",
        hypothesis_id="H2_ZT_KEYS",
        location="zabbix_web_view.py:_build_payload",
        message="Checking ZeroTier metrics keys",
        data={
            "has_net_in": (mm.get("net.if.in[zttqhuceey]") is not None),
            "has_net_out": (mm.get("net.if.out[zttqhuceey]") is not None),
        },
    )

    payload = {
        "host": ZABBIX_HOST_NAME,
        "api_url": ZABBIX_API_URL,
        "timestamp": current_time_vn,
        "summary": {
            "cpu_util": _metric(mm, "system.cpu.util"),
            "ram_util": _metric(mm, "vm.memory.utilization"),
            "disk_used": _metric(mm, "vfs.fs.size[/,pused]"),
            "net_in": _metric(mm, "net.if.in[zttqhuceey]"),
            "net_out": _metric(mm, "net.if.out[zttqhuceey]"),
            "uptime": _fmt_uptime((mm.get("system.uptime") or {}).get("lastvalue")),
        },
        "rows": [
            {
                "key": k,
                "name": (mm.get(k) or {}).get("name") or "-",
                "value": (mm.get(k) or {}).get("lastvalue") if mm.get(k) else "N/A",
                "units": (mm.get(k) or {}).get("units") if mm.get(k) else "",
                "lastclock": (mm.get(k) or {}).get("lastclock") if mm.get(k) else "",
            }
            for k in KEYS
        ],
    }
    _debug89_log(
        run_id="zabbix-web-view",
        hypothesis_id="H3_KEYS_EXPANDED",
        location="zabbix_web_view.py:_build_payload",
        message="Payload rows built from KEYS",
        data={
            "keys_total": len(KEYS),
            "rows_total": len(payload["rows"]),
            "has_hostname": bool(mm.get("system.hostname")),
        },
    )
    return payload


@app.route("/health", methods=["GET"])
def health() -> Response:
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat() + "Z"})


@app.route("/api/zabbix", methods=["GET"])
def zabbix_view() -> Response:
    output = request.args.get("output", "html").strip().lower()
    try:
        data = _build_payload()
    except Exception as exc:
        # #region agent log
        _debug_log(
            run_id="zbx-view",
            hypothesis_id="H3_RUNTIME_ERROR",
            location="zabbix_web_view.py:/api/zabbix",
            message="Failed collecting zabbix metrics",
            data={"error": str(exc)},
        )
        # #endregion agent log
        if output == "json":
            return jsonify({"ok": False, "error": str(exc)})
        return Response(
            f"<h3>Zabbix Error</h3><pre>{str(exc)}</pre><p>Try /api/zabbix?output=json for details.</p>",
            status=500,
            mimetype="text/html",
        )

    if output == "json":
        return jsonify({"ok": True, **data})

    s = data["summary"]
    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Zabbix Metrics</title>
  <style>
    body{{font-family:Segoe UI,Arial,sans-serif;background:#0b1220;color:#e6f1ff;margin:0;padding:20px}}
    .head{{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}}
    .muted{{color:#8ca8c7;font-size:12px}}
    .grid{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-bottom:16px}}
    .card{{background:#101b31;border:1px solid #1f3555;border-radius:10px;padding:12px}}
    .k{{font-size:12px;color:#9fc0ea}} .v{{font-size:20px;font-weight:700;color:#7ee6ff}}
    #metricsListWrap{{max-height:360px;overflow-y:auto;border-radius:10px}}
    table{{width:100%;border-collapse:collapse;background:#101b31;border:1px solid #1f3555;border-radius:10px;overflow:hidden}}
    th,td{{padding:10px;border-bottom:1px solid #1f3555;text-align:left;font-size:13px}}
    th{{background:#0f1830;color:#a9cbef;position:sticky;top:0;z-index:2}}
    tr:hover td{{background:#13213d}}
    .actions{{margin-bottom:12px}}
    .btn{{display:inline-block;padding:8px 12px;background:#17365f;color:#e9f5ff;border-radius:8px;text-decoration:none;border:1px solid #2e5b98}}
    #metricsListWrap::-webkit-scrollbar{{width:6px}}
    #metricsListWrap::-webkit-scrollbar-track{{background:rgba(2,8,18,.45)}}
    #metricsListWrap::-webkit-scrollbar-thumb{{background:rgba(0,212,255,.35);border-radius:10px;box-shadow:0 0 14px rgba(0,212,255,.15)}}
    #metricsListWrap::-webkit-scrollbar-thumb:hover{{background:rgba(0,212,255,.55)}}
  </style>
</head>
<body>
  <div class="head">
    <div>
      <h2 style="margin:0">Zabbix Metrics · {data['host']}</h2>
      <div class="muted">API: {data['api_url']} · Updated: {data['timestamp']}</div>
    </div>
    <div class="actions">
      <a class="btn" href="/api/zabbix">Refresh</a>
      <a class="btn" href="/api/zabbix?output=json">JSON</a>
    </div>
  </div>
  <div class="grid">
    <div class="card"><div class="k">CPU Utilization</div><div class="v">{s['cpu_util']}</div></div>
    <div class="card"><div class="k">RAM Utilization</div><div class="v">{s['ram_util']}</div></div>
    <div class="card"><div class="k">Disk Used /</div><div class="v">{s['disk_used']}</div></div>
    <div class="card"><div class="k">Network In</div><div class="v">{s['net_in']}</div></div>
    <div class="card"><div class="k">Network Out</div><div class="v">{s['net_out']}</div></div>
    <div class="card"><div class="k">Uptime</div><div class="v">{s['uptime']}</div></div>
  </div>
  <div id="metricsListWrap">
    <table>
      <thead>
        <tr><th>Key</th><th>Name</th><th>Value</th><th>Units</th><th>Last Clock</th></tr>
      </thead>
      <tbody id="metricsRowsBody">
        <tr><td colspan="5" class="muted" style="padding:16px;text-align:center">Loading metrics…</td></tr>
      </tbody>
    </table>
  </div>

  <script>
    async function loadMetricsRows() {{
      try {{
        const res = await fetch('/api/zabbix?output=json', {{ cache: 'no-store' }});
        const d = await res.json();
        const rows = d.rows || [];
        const tbody = document.getElementById('metricsRowsBody');
        const esc = (x) => String(x ?? '').replace(/</g,'&lt;');
        tbody.innerHTML = rows.map(r => '<tr>' +
          '<td>' + esc(r.key) + '</td>' +
          '<td>' + esc(r.name) + '</td>' +
          '<td>' + esc(r.value) + '</td>' +
          '<td>' + esc(r.units) + '</td>' +
          '<td>' + esc(r.lastclock) + '</td>' +
        '</tr>').join('');
      }} catch(e) {{
        console.warn('loadMetricsRows', e);
      }}
    }}
    loadMetricsRows();
  </script>
</body>
</html>
"""
    return Response(html, mimetype="text/html")


if __name__ == "__main__":
    # #region agent log
    _debug_log(
        run_id="zbx-view",
        hypothesis_id="H4_SERVER_BOOT",
        location="zabbix_web_view.py:__main__",
        message="Starting zabbix web view app",
        data={"host": APP_HOST, "port": APP_PORT},
    )
    _debug396_log(
        run_id="boot",
        hypothesis_id="H1_H2",
        location="zabbix_web_view.py:__main__",
        message="bind_port_resolution",
        data={
            "APP_PORT_env": os.environ.get("APP_PORT"),
            "APP_HOST": APP_HOST,
            "resolved_APP_PORT": APP_PORT,
            "start_server_bat_opens": 5001,
            "mismatch_5001_vs_bind": APP_PORT != 5001,
        },
    )
    # #endregion agent log
    app.run(host=APP_HOST, port=APP_PORT, debug=False)

