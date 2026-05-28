from __future__ import annotations
import re, shlex
_AUTH_HEADER_PATTERN = re.compile(r"^(authorization|cookie|set-cookie|x-auth-token|x-api-key|x-access-token|x-session-token|bearer)$", re.I)

def sanitize_headers(headers: dict | None) -> dict:
    return {k: ("<redacted>" if _AUTH_HEADER_PATTERN.match(k) else v) for k, v in dict(headers or {}).items()}

def sanitize_for_postgres(value: str) -> str:
    return value.replace("\x00", "") if value else value

def request_to_curl(request: dict) -> str:
    method = request.get("method", "GET").upper(); url = request.get("url", ""); headers = request.get("headers", {}) or {}; body = request.get("body")
    parts = ["curl"]
    if method != "GET": parts.append(f"-X {method}")
    parts.append(shlex.quote(url))
    for k, v in headers.items(): parts.append("-H " + shlex.quote(f"{k}: {v}"))
    if body: parts.append("--data-raw " + shlex.quote(body))
    return " \\\n  ".join(parts)
