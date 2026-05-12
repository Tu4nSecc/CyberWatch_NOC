from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import requests


@dataclass
class ZabbixConfig:
    api_url: str
    username: str
    password: str
    timeout_sec: int = 20


# Zabbix history: 0=numeric float, 1=character, 2=log, 3=numeric unsigned, 4=text
def history_type_from_value_type(value_type: Any) -> int:
    try:
        vt = int(value_type)
    except Exception:
        return 0
    if vt in (0, 1, 2, 3, 4):
        return vt
    return 0


class ZabbixClient:
    def __init__(self, config: ZabbixConfig):
        self.config = config
        self._token: Optional[str] = None
        self._request_id = 1
        self._auth_mode = "json_auth"  # json_auth | bearer_header

    def _rpc(self, method: str, params: Dict[str, Any], auth_required: bool = True) -> Any:
        def _post(use_payload_auth: bool, use_header_bearer: bool) -> Any:
            payload: Dict[str, Any] = {
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
                "id": self._request_id,
            }
            headers = {"Content-Type": "application/json-rpc"}
            if auth_required and use_payload_auth:
                payload["auth"] = self._token
            if auth_required and use_header_bearer and self._token:
                headers["Authorization"] = f"Bearer {self._token}"

            res = requests.post(self.config.api_url, json=payload, headers=headers, timeout=self.config.timeout_sec)
            res.raise_for_status()
            body = res.json()
            if "error" in body:
                raise RuntimeError(f"Zabbix API error: {body['error']}")
            return body.get("result")

        self._request_id += 1
        if not auth_required:
            return _post(use_payload_auth=False, use_header_bearer=False)

        if self._auth_mode == "json_auth":
            try:
                return _post(use_payload_auth=True, use_header_bearer=False)
            except RuntimeError as exc:
                msg = str(exc).lower()
                if "unexpected parameter \"auth\"" in msg:
                    self._auth_mode = "bearer_header"
                    return _post(use_payload_auth=False, use_header_bearer=True)
                raise

        return _post(use_payload_auth=False, use_header_bearer=True)

    def login(self) -> str:
        if self._token:
            return self._token

        try:
            result = self._rpc(
                "user.login",
                {"username": self.config.username, "password": self.config.password},
                auth_required=False,
            )
        except RuntimeError as exc:
            if "unexpected parameter \"username\"" in str(exc).lower():
                result = self._rpc(
                    "user.login",
                    {"user": self.config.username, "password": self.config.password},
                    auth_required=False,
                )
            else:
                raise
        self._token = str(result)
        return self._token

    def _enrich_problems_with_hosts(self, problems: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """When problem.get cannot return hosts, map triggerid -> hosts via trigger.get."""
        if not problems:
            return problems
        tids: List[str] = []
        for p in problems:
            if str(p.get("source") or "") == "0" and p.get("objectid"):
                tids.append(str(p.get("objectid")))
        if not tids:
            return problems
        uniq = list(dict.fromkeys(tids))
        try:
            triggers = self._rpc(
                "trigger.get",
                {
                    "output": ["triggerid"],
                    "triggerids": uniq,
                    "selectHosts": ["hostid", "host", "name"],
                },
            )
        except RuntimeError:
            try:
                triggers = self._rpc(
                    "trigger.get",
                    {
                        "output": ["triggerid"],
                        "triggerids": uniq,
                        "selectHosts": "extend",
                    },
                )
            except RuntimeError:
                return problems
        tm: Dict[str, Any] = {t["triggerid"]: t.get("hosts") or [] for t in (triggers or [])}
        for p in problems:
            tid = str(p.get("objectid") or "")
            if tid in tm:
                p["hosts"] = tm[tid]
        return problems

    def problem_get(
        self,
        *,
        limit: int = 200,
        min_severity: int = 1,
        recent: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        min_severity: 1=Warning..4=Disaster. Use 0 to include Information.
        """
        self.login()
        params: Dict[str, Any] = {
            "output": "extend",
            "selectTags": "extend",
            "sortfield": ["eventid"],
            "sortorder": "DESC",
            "recent": recent,
            "limit": limit,
        }
        if min_severity > 0:
            # Zabbix severities 1..5 (Information..Disaster); range must include 5.
            params["severities"] = [s for s in range(int(min_severity), 6)]

        def _call(params_in: Dict[str, Any], hosts_mode: Optional[str]) -> List[Dict[str, Any]]:
            p = dict(params_in)
            if hosts_mode == "extend":
                p["selectHosts"] = "extend"
            elif hosts_mode == "list":
                p["selectHosts"] = ["hostid", "host", "name"]
            return self._rpc("problem.get", p)

        def _filter_sev(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
            out: List[Dict[str, Any]] = []
            for r in rows or []:
                try:
                    if int(r.get("severity", 0)) >= int(min_severity):
                        out.append(r)
                except Exception:
                    if int(min_severity) <= 0:
                        out.append(r)
            return out

        try:
            return _call(params, "extend")
        except RuntimeError as exc:
            msg = str(exc).lower()
            if "severities" in msg and ("unexpected" in msg or "invalid" in msg):
                p2 = dict(params)
                p2.pop("severities", None)
                try:
                    rows = _call(p2, "extend")
                    return _filter_sev(list(rows or []))
                except RuntimeError as exc2:
                    msg2 = str(exc2).lower()
                    if "selecthosts" in msg2 or "unexpected parameter" in msg2:
                        rows = _call(p2, None)
                        return _filter_sev(self._enrich_problems_with_hosts(list(rows or [])))
                    raise
            if "selecthosts" in msg or "unexpected parameter" in msg:
                try:
                    return _call(params, "list")
                except RuntimeError:
                    rows = _call(params, None)
                    return self._enrich_problems_with_hosts(list(rows or []))
            raise

    def history_get(
        self,
        itemids: List[str],
        history_type: int = 0,
        *,
        limit: int = 200,
        time_from: Optional[int] = None,
        time_till: Optional[int] = None,
        sortorder: str = "DESC",
    ) -> List[Dict[str, Any]]:
        self.login()
        req: Dict[str, Any] = {
            "output": "extend",
            "history": history_type,
            "itemids": itemids,
            "sortfield": "clock",
            "sortorder": sortorder,
            "limit": limit,
        }
        if time_from is not None:
            req["time_from"] = int(time_from)
        if time_till is not None:
            req["time_till"] = int(time_till)
        return self._rpc("history.get", req)

    def host_id_by_name(self, name: str) -> Optional[str]:
        self.login()
        hosts = self._rpc(
            "host.get",
            {
                "output": ["hostid", "name", "host"],
                "filter": {"name": [name]},
            },
        )
        if hosts:
            return str(hosts[0].get("hostid"))
        hosts = self._rpc(
            "host.get",
            {
                "output": ["hostid", "name", "host"],
                "search": {"name": name},
            },
        )
        if hosts:
            return str(hosts[0].get("hostid"))
        return None

    def items_for_host(self, host_id: str, keys: List[str]) -> Dict[str, Dict[str, Any]]:
        """Return map key_ -> item row (itemid, key_, lastvalue, value_type, units)."""
        self.login()
        if not keys:
            return {}
        items = self._rpc(
            "item.get",
            {
                "output": ["itemid", "key_", "lastvalue", "units", "value_type", "lastclock"],
                "hostids": [host_id],
                "monitored": True,
                "filter": {"key_": keys},
            },
        )
        out: Dict[str, Dict[str, Any]] = {}
        for it in items or []:
            k = str(it.get("key_") or "")
            if k:
                out[k] = it
        missing = [k for k in keys if k not in out]
        if not missing:
            return out
        # Fallback: some Zabbix versions are picky about filter list — fetch subset by search.
        for k in missing:
            found = self._rpc(
                "item.get",
                {
                    "output": ["itemid", "key_", "lastvalue", "units", "value_type", "lastclock"],
                    "hostids": [host_id],
                    "monitored": True,
                    "search": {"key_": k},
                    "limit": 5,
                },
            )
            for it in found or []:
                if str(it.get("key_") or "") == k:
                    out[k] = it
                    break
        return out

    def latest_value_for_item(self, item: Dict[str, Any], history_type: Optional[int] = None) -> Tuple[Optional[float], Optional[str]]:
        """
        Prefer lastvalue; if empty, pull latest history point using value_type when history_type not given.
        Returns (numeric_or_none, text_or_none).
        """
        self.login()
        raw = item.get("lastvalue")
        if raw is not None and str(raw) != "":
            vt = history_type if history_type is not None else history_type_from_value_type(item.get("value_type"))
            if vt in (0, 3):
                try:
                    return float(raw), None
                except Exception:
                    return None, str(raw)
            return None, str(raw)

        itemid = str(item.get("itemid") or "")
        if not itemid:
            return None, None
        vt = history_type if history_type is not None else history_type_from_value_type(item.get("value_type"))
        rows = self.history_get([itemid], history_type=vt, limit=1)
        if not rows:
            return None, None
        val = rows[0].get("value")
        if vt in (0, 3):
            try:
                return float(val), None
            except Exception:
                return None, str(val)
        return None, str(val)

    def item_find(self, search_key: str) -> Optional[str]:
        self.login()
        items = self._rpc(
            "item.get",
            {
                "output": ["itemid", "name", "key_"],
                "search": {"key_": search_key},
                "sortfield": "itemid",
                "sortorder": "DESC",
                "limit": 1,
            },
        )
        if not items:
            return None
        return str(items[0].get("itemid"))

    def latest_metric(self, search_key: str, history_type: int = 0) -> Optional[float]:
        itemid = self.item_find(search_key)
        if not itemid:
            return None
        rows = self.history_get([itemid], history_type=history_type, limit=1)
        if not rows:
            return None
        try:
            return float(rows[0].get("value"))
        except Exception:
            return None
