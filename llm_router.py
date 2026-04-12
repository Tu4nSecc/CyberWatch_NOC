import os
import time
import logging
from typing import Callable, Dict, Any, List, Optional
import requests
logger = logging.getLogger(__name__)
# =========================
# Cấu hình provider
# =========================
GEMINI_API_KEY   = os.environ.get("GEMINI_API_KEY", "")
GROQ_API_KEY     = os.environ.get("GROQ_API_KEY", "")
OPENROUTER_KEY   = os.environ.get("OPENROUTER_API_KEY", "")
GEMINI_MODEL     = os.environ.get("GEMINI_MODEL", "gemini-1.5-flash")
GROQ_MODEL       = os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant")
OPENROUTER_MODEL = os.environ.get("OPENROUTER_MODEL", "meta-llama/llama-3.1-8b-instruct")
HTTP_TIMEOUT_SEC = 30
MIN_INTERVAL_SEC = 0.3   # delay tối thiểu giữa 2 call / provider
MAX_RETRIES      = 3
BASE_BACKOFF     = 1.0   # giây
_last_call_ts: Dict[str, float] = {}  # provider -> timestamp lần call gần nhất
# =========================
# Helper: rate limit đơn giản
# =========================
def _respect_rate_limit(provider: str, min_interval: float = MIN_INTERVAL_SEC) -> None:
    now = time.time()
    last = _last_call_ts.get(provider)
    if last is not None:
        delta = now - last
        if delta < min_interval:
            sleep_for = min_interval - delta
            logger.debug("Rate-limit %s: sleep %.3fs", provider, sleep_for)
            time.sleep(sleep_for)
    _last_call_ts[provider] = time.time()
# =========================
# Provider clients
# =========================
def _call_gemini(prompt: str, max_tokens: int = 1500) -> str:
    if not GEMINI_API_KEY:
        raise RuntimeError("GEMINI_API_KEY is not set")
    _respect_rate_limit("gemini")
    url = f"https://generativelanguage.googleapis.com/v1/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
    payload = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "maxOutputTokens": max_tokens,
            "temperature": 0.2,
        },
    }
    r = requests.post(url, json=payload, timeout=HTTP_TIMEOUT_SEC)
    if not r.ok:
        logger.warning("Gemini HTTP %s: %s", r.status_code, r.text[:200])
        r.raise_for_status()
    data = r.json() or {}
    cands = data.get("candidates") or []
    if not cands:
        return ""
    parts = (cands[0].get("content") or {}).get("parts") or []
    text = "".join((p.get("text") or "") for p in parts)
    return text.strip()
def _call_groq(prompt: str, max_tokens: int = 1500) -> str:
    if not GROQ_API_KEY:
        raise RuntimeError("GROQ_API_KEY is not set")
    _respect_rate_limit("groq")
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "user", "content": prompt},
        ],
        "max_tokens": max_tokens,
        "temperature": 0.2,
    }
    r = requests.post(url, json=payload, headers=headers, timeout=HTTP_TIMEOUT_SEC)
    if not r.ok:
        logger.warning("Groq HTTP %s: %s", r.status_code, r.text[:200])
        r.raise_for_status()
    data = r.json() or {}
    choices = data.get("choices") or []
    if not choices:
        return ""
    return (choices[0].get("message", {}).get("content") or "").strip()
def _call_openrouter(prompt: str, max_tokens: int = 1500) -> str:
    if not OPENROUTER_KEY:
        raise RuntimeError("OPENROUTER_API_KEY is not set")
    _respect_rate_limit("openrouter")
    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {OPENROUTER_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://your-soc-dashboard.local",
        "X-Title": "SOC-AI Analyst",
    }
    payload = {
        "model": OPENROUTER_MODEL,
        "messages": [
            {"role": "user", "content": prompt},
        ],
        "max_tokens": max_tokens,
        "temperature": 0.3,
    }
    r = requests.post(url, json=payload, headers=headers, timeout=HTTP_TIMEOUT_SEC)
    if not r.ok:
        logger.warning("OpenRouter HTTP %s: %s", r.status_code, r.text[:200])
        r.raise_for_status()
    data = r.json() or {}
    choices = data.get("choices") or []
    if not choices:
        return ""
    return (choices[0].get("message", {}).get("content") or "").strip()
PROVIDERS: Dict[str, Callable[[str, int], str]] = {
    "gemini": _call_gemini,
    "groq": _call_groq,
    "openrouter": _call_openrouter,
}
# =========================
# Retry + backoff
# =========================
def call_with_retry(
    provider_name: str,
    prompt: str,
    max_tokens: int,
    max_retries: int = MAX_RETRIES,
    base_backoff: float = BASE_BACKOFF,
) -> str:
    fn = PROVIDERS[provider_name]
    attempt = 0
    while True:
        try:
            return fn(prompt, max_tokens)
        except requests.HTTPError as e:
            status = getattr(e.response, "status_code", None)
            body = (getattr(e.response, "text", "") or "")[:200]
            logger.error("%s HTTPError %s: %s", provider_name, status, body)
            # 429 hoặc 5xx → có thể retry
            if status in (429, 500, 502, 503, 504) and attempt < max_retries:
                delay = base_backoff * (2 ** attempt)
                logger.warning("%s retry %d/%d sau %.1fs", provider_name, attempt + 1, max_retries, delay)
                time.sleep(delay)
                attempt += 1
                continue
            raise
        except (requests.Timeout, requests.ConnectionError) as e:
            logger.error("%s network error: %s", provider_name, e)
            if attempt < max_retries:
                delay = base_backoff * (2 ** attempt)
                logger.warning("%s retry %d/%d sau %.1fs", provider_name, attempt + 1, max_retries, delay)
                time.sleep(delay)
                attempt += 1
                continue
            raise
        except Exception as e:
            logger.exception("%s unexpected error: %s", provider_name, e)
            raise
# =========================
# Router: chọn provider + fallback
# =========================
def pick_chain(task_type: str) -> List[str]:
    """
    Chọn thứ tự provider theo loại tác vụ.
    task_type: "fast", "analysis", "chat", ...
    """
    if task_type == "fast":
        # ví dụ: câu trả lời nhanh, ít tokens → Groq ưu tiên
        return ["groq", "gemini", "openrouter"]
    if task_type == "analysis":
        # phân tích SOC nặng, nhiều ngữ cảnh → Gemini trước
        return ["gemini", "groq", "openrouter"]
    # mặc định
    return ["gemini", "groq", "openrouter"]
def route_llm(
    prompt: str,
    task_type: str = "analysis",
    max_tokens: int = 1500,
) -> str:
    chain = pick_chain(task_type)
    last_error: Optional[Exception] = None
    for provider in chain:
        try:
            logger.info("Call LLM provider=%s task_type=%s", provider, task_type)
            return call_with_retry(provider, prompt, max_tokens)
        except Exception as e:
            last_error = e
            logger.warning("Provider %s failed, fallback tiếp...", provider)
    # nếu tất cả provider đều fail, ném lỗi cuối
    raise RuntimeError(f"All providers failed for task_type={task_type}") from last_error