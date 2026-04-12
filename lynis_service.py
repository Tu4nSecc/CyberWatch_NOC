"""
Remote Lynis audit over SSH with SSE-friendly streaming.
Lab use only — credentials travel in POST body; restrict network access in production.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

# #region agent log
_DEBUG_LOG_PATH = Path(__file__).resolve().parent / "debug-f300aa.log"
_DEBUG_SESSION = "f300aa"


def _agent_log(*, hypothesis_id: str, location: str, message: str, data: Dict[str, Any], run_id: str = "lynis") -> None:
    payload = {
        "sessionId": _DEBUG_SESSION,
        "runId": run_id,
        "hypothesisId": hypothesis_id,
        "location": location,
        "message": message,
        "data": data,
        "timestamp": int(time.time() * 1000),
    }
    try:
        _DEBUG_LOG_PATH.open("a", encoding="utf-8").write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        pass


# #endregion agent log


def _sse_data(obj: Dict[str, Any]) -> str:
    return f"data: {json.dumps(obj, ensure_ascii=False)}\n\n"


def _sse_complete(payload: Dict[str, Any]) -> str:
    return f"event: complete\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"


def build_remote_command(sudo_pass: str) -> str:
    import shlex

    sp = shlex.quote(sudo_pass)
    # NOTE: Lynis validates ownership when running as root.
    # We clone as the SSH user, then chown the whole tree to root:root before sudo execution.
    # `-p ''` reduces sudo prompt noise in the streamed terminal.
    return (
        "git clone https://github.com/CISOfy/lynis.git /tmp/lynis_temp 2>&1 && "
        f"echo {sp} | sudo -S -p '' chown -R root:root /tmp/lynis_temp 2>&1 && "
        "cd /tmp/lynis_temp && "
        f"echo {sp} | sudo -S -p '' ./lynis audit system --quick --no-colors 2>&1; "
        f"echo {sp} | sudo -S -p '' rm -rf /tmp/lynis_temp 2>&1"
    )


def parse_lynis_output(full_text: str) -> Dict[str, Any]:
    text = full_text or ""
    hardening_index: Optional[int] = None
    warnings = 0
    suggestions = 0

    m = re.search(r"Hardening index\s*:\s*(?:\[[^\]]*\]\s*)?(\d+)\s*%", text, re.IGNORECASE)
    if m:
        hardening_index = int(m.group(1))
    m = re.search(r"(?:^|\n)\s*Warnings?\s*:\s*(\d+)", text, re.IGNORECASE | re.MULTILINE)
    if m:
        warnings = int(m.group(1))
    m = re.search(r"(?:^|\n)\s*Suggestions?\s*:\s*(\d+)", text, re.IGNORECASE | re.MULTILINE)
    if m:
        suggestions = int(m.group(1))

    return {
        "hardening_index": hardening_index,
        "warnings": warnings,
        "suggestions": suggestions,
    }


def build_ai_findings(stats: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Mock analyst rows; tuned to typical Lynis themes."""
    hi = stats.get("hardening_index")
    w = stats.get("warnings") or 0
    s = stats.get("suggestions") or 0
    return [
        {
            "severity": "Cao",
            "category": "Xác thực",
            "finding": "Quyền truy cập tệp `/etc/passwd` có thể quá rộng, hoặc dấu hiệu cấu hình quyền tệp nhạy cảm chưa chuẩn hoá (phát hiện thường gặp của Lynis).",
            "remediation": "Thực hiện `chmod 644 /etc/passwd`, `chmod 640 /etc/shadow`, kiểm tra ownership `root:root`; sau đó chạy lại Lynis để xác nhận khuyến nghị/ID kiểm tra (ví dụ [AUTH-9286]).",
        },
        {
            "severity": "Cảnh báo",
            "category": "Dịch vụ SSH",
            "finding": "Cấu hình SSH có thể cho phép đăng nhập root hoặc sử dụng các tuỳ chọn chưa an toàn (tuỳ thuộc `sshd_config`).",
            "remediation": "Thiết lập `PermitRootLogin no`, cân nhắc tắt `PasswordAuthentication` (ưu tiên SSH key theo chính sách); kiểm tra cấu hình bằng `sshd -t`, sau đó restart `sshd` và xác minh truy cập hợp lệ.",
        },
        {
            "severity": "Cảnh báo",
            "category": "Kernel / Gia cố",
            "finding": f"Kết quả quét ghi nhận {w} cảnh báo và {s} gợi ý; baseline gia cố (sysctl/kernel hardening) có thể chưa đầy đủ.",
            "remediation": "Áp dụng baseline sysctl (ví dụ `rp_filter`, `icmp_ignore_bogus_error_responses`, hardening network stack) theo chuẩn của lab/tổ chức; quản lý override rõ ràng trong `/etc/sysctl.d/` và kiểm thử hồi quy sau thay đổi.",
        },
        {
            "severity": "Thông tin",
            "category": "Tư thế bảo mật",
            "finding": f"Hardening Index hiện tại: {hi if hi is not None else 'N/A'}%. Nên theo dõi liên tục và so sánh theo thời gian.",
            "remediation": "Lên lịch chạy Lynis định kỳ (ví dụ hàng tuần), theo dõi biến động chỉ số, và đưa các phát hiện vào quy trình xử lý của SOC (ticket/change control) để đóng rủi ro có kiểm soát.",
        },
    ]


def run_lynis_ssh_stream(
    *,
    target_ip: str,
    user: str,
    ssh_pass: str,
    sudo_pass: str,
    port: int = 22,
) -> Generator[str, None, Tuple[str, Optional[str]]]:
    """
    Yields SSE chunks (full lines including `data: ...` or `event: complete`).
    Returns (accumulated_output, error_message) via StopIteration value — we use a wrapper instead.
    """
    accumulated: List[str] = []
    err_msg: Optional[str] = None

    try:
        import paramiko
    except ImportError:
        yield _sse_data({"type": "error", "message": "paramiko not installed. pip install paramiko"})
        yield _sse_complete(
            {
                "ok": False,
                "stats": parse_lynis_output(""),
                "findings": [],
                "error": "paramiko missing",
            }
        )
        return

    cmd = build_remote_command(sudo_pass)
    # #region agent log
    _agent_log(
        hypothesis_id="H1_SSH",
        location="lynis_service.py:run_lynis_ssh_stream",
        message="SSH Lynis starting",
        data={"target": target_ip, "user": user, "port": port, "cmdLen": len(cmd)},
    )
    # #endregion agent log

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=target_ip,
            port=port,
            username=user,
            password=ssh_pass,
            timeout=60,
            banner_timeout=60,
            auth_timeout=60,
        )
    except Exception as exc:
        err_msg = str(exc)
        # #region agent log
        _agent_log(
            hypothesis_id="H1_SSH",
            location="lynis_service.py:run_lynis_ssh_stream",
            message="SSH connect failed",
            data={"error": err_msg},
        )
        # #endregion agent log
        yield _sse_data({"type": "error", "message": f"SSH connection failed: {err_msg}"})
        yield _sse_complete(
            {
                "ok": False,
                "stats": parse_lynis_output(""),
                "findings": build_ai_findings({"hardening_index": None, "warnings": 0, "suggestions": 0}),
                "error": err_msg,
            }
        )
        return

    yield _sse_data({"type": "log", "line": f"[+] SSH session established to {target_ip} as {user}\n"})

    try:
        _stdin, stdout, _stderr = client.exec_command(cmd, get_pty=True, timeout=3600)
        while True:
            line = stdout.readline()
            if line:
                accumulated.append(line)
                yield _sse_data({"type": "log", "line": line})
            elif stdout.channel.exit_status_ready():
                break
            else:
                time.sleep(0.05)

        tail = stdout.read().decode("utf-8", errors="replace")
        if tail:
            accumulated.append(tail)
            yield _sse_data({"type": "log", "line": tail})

        exit_status = stdout.channel.recv_exit_status()
        # #region agent log
        _agent_log(
            hypothesis_id="H2_STREAM",
            location="lynis_service.py:run_lynis_ssh_stream",
            message="SSH channel closed",
            data={"exitStatus": exit_status, "bytesOut": sum(len(x) for x in accumulated)},
        )
        # #endregion agent log

        if exit_status != 0:
            yield _sse_data(
                {
                    "type": "log",
                    "line": f"\n[!] Remote command exit code: {exit_status}\n",
                }
            )

    except Exception as exc:
        err_msg = str(exc)
        yield _sse_data({"type": "error", "message": err_msg})
    finally:
        client.close()

    full_text = "".join(accumulated)
    stats = parse_lynis_output(full_text)
    findings = build_ai_findings(stats)

    # #region agent log
    _agent_log(
        hypothesis_id="H3_PARSE",
        location="lynis_service.py:run_lynis_ssh_stream",
        message="Lynis parse result",
        data={"stats": stats, "ok": err_msg is None},
    )
    # #endregion agent log

    yield _sse_complete(
        {
            "ok": err_msg is None,
            "stats": stats,
            "findings": findings,
            "error": err_msg,
            "exit_note": None,
        }
    )


def iter_sse_lynis_scan(**kwargs: Any) -> Generator[str, None, None]:
    """Flatten generator for Flask stream_with_context."""
    yield from run_lynis_ssh_stream(**kwargs)
