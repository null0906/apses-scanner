from __future__ import annotations
import hashlib
import re, shlex
from dataclasses import dataclass
_AUTH_HEADER_PATTERN = re.compile(r"^(authorization|cookie|set-cookie|x-auth-token|x-api-key|x-access-token|x-session-token|bearer)$", re.I)

def sanitize_headers(headers: dict | None) -> dict:
    return {k: ("<redacted>" if _AUTH_HEADER_PATTERN.match(k) else v) for k, v in dict(headers or {}).items()}

def sanitize_for_postgres(value: str) -> str:
    return value.replace("\x00", "") if value else value


@dataclass(frozen=True)
class SPAShellFingerprint:
    content_type: str
    body_hash: str
    body_size: int
    looks_like_shell: bool


def fingerprint_spa_shell(headers: dict | None, body: str | bytes | None) -> SPAShellFingerprint:
    text = body.decode(errors="replace") if isinstance(body, bytes) else str(body or "")
    content_type = str(dict(headers or {}).get("content-type", "")).split(";", 1)[0].strip().lower()
    lowered = text.lower()
    looks_like_shell = "text/html" in content_type and (
        "<app-root" in lowered or ("<script" in lowered and "</html>" in lowered)
    )
    return SPAShellFingerprint(
        content_type=content_type,
        body_hash=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        body_size=len(text.encode("utf-8")),
        looks_like_shell=looks_like_shell,
    )


def matches_spa_shell(fingerprint: SPAShellFingerprint, headers: dict | None, body: str | bytes | None) -> bool:
    candidate = fingerprint_spa_shell(headers, body)
    if candidate.content_type != fingerprint.content_type:
        return False
    if candidate.body_hash == fingerprint.body_hash:
        return True
    if not fingerprint.looks_like_shell or not candidate.looks_like_shell:
        return False
    return abs(candidate.body_size - fingerprint.body_size) <= max(128, int(fingerprint.body_size * 0.02))

def request_to_curl(request: dict) -> str:
    method = request.get("method", "GET").upper(); url = request.get("url", ""); headers = request.get("headers", {}) or {}; body = request.get("body")
    parts = ["curl"]
    if method != "GET": parts.append(f"-X {method}")
    parts.append(shlex.quote(url))
    for k, v in headers.items(): parts.append("-H " + shlex.quote(f"{k}: {v}"))
    if body: parts.append("--data-raw " + shlex.quote(body))
    return " \\\n  ".join(parts)
