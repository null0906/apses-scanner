from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from .ratelimit import RateLimiter

_BODY_MUTATION_HEADERS = {"content-length", "transfer-encoding"}
_REPLAY_STRIP_HEADERS = _BODY_MUTATION_HEADERS | {
    "if-none-match", "if-modified-since", "if-match", "if-unmodified-range", "if-range"
}


@dataclass(frozen=True)
class ReplayRequest:
    method: str
    url: str
    headers: dict[str, str]
    body: str | bytes | None = None

    def sanitized_headers(self) -> dict[str, str]:
        return {k: v for k, v in (self.headers or {}).items() if k.lower() not in _REPLAY_STRIP_HEADERS}

    def with_query_param(self, name: str, value: str) -> "ReplayRequest":
        parts = urlsplit(self.url)
        params = parse_qsl(parts.query, keep_blank_values=True)
        updated = False
        new_params: list[tuple[str, str]] = []
        for key, existing in params:
            if key == name:
                new_params.append((key, value)); updated = True
            else:
                new_params.append((key, existing))
        if not updated:
            new_params.append((name, value))
        return replace(self, url=urlunsplit(parts._replace(query=urlencode(new_params, doseq=True))))

    def with_body_param(self, name: str, value: str) -> "ReplayRequest":
        raw = self.body.decode() if isinstance(self.body, bytes) else (self.body or "")
        params = parse_qsl(raw, keep_blank_values=True)
        updated = False
        new_params: list[tuple[str, str]] = []
        for key, existing in params:
            if key == name:
                new_params.append((key, value)); updated = True
            else:
                new_params.append((key, existing))
        if not updated:
            new_params.append((name, value))
        body = urlencode(new_params, doseq=True)
        return replace(self, body=body, headers=self.sanitized_headers())

    def with_json_body_param(self, path: str, value: Any) -> "ReplayRequest":
        raw = self.body.decode() if isinstance(self.body, bytes) else (self.body or "{}")
        try:
            data = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            data = {}
        if not isinstance(data, (dict, list)):
            data = {}
        _set_json_path(data, path, value)
        body = json.dumps(data, separators=(",", ":"))
        headers = self.sanitized_headers()
        headers.setdefault("Content-Type", "application/json")
        return replace(self, body=body, headers=headers)

    def without_headers(self, names: set[str]) -> "ReplayRequest":
        lowered = {n.lower() for n in names}
        return replace(self, headers={k: v for k, v in (self.headers or {}).items() if k.lower() not in lowered})


def _set_json_path(root: Any, path: str, value: Any) -> None:
    pieces = [p for p in re.split(r"\.|\[|\]", path) if p != ""]
    if not pieces:
        return
    cur = root
    for part in pieces[:-1]:
        idx = int(part) if part.isdigit() else None
        if idx is not None and isinstance(cur, list):
            while len(cur) <= idx:
                cur.append({})
            cur = cur[idx]
        elif isinstance(cur, dict):
            cur = cur.setdefault(part, {})
        else:
            return
    last = pieces[-1]
    if last.isdigit() and isinstance(cur, list):
        idx = int(last)
        while len(cur) <= idx:
            cur.append(None)
        cur[idx] = value
    elif isinstance(cur, dict):
        cur[last] = value


@dataclass(frozen=True)
class ReplayResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes
    elapsed_ms: float = 0.0
    url: str = ""

    @property
    def text(self) -> str:
        try:
            return self.body.decode("utf-8", errors="replace")
        except Exception:
            return ""

    @property
    def body_text(self) -> str:
        return self.text

    @property
    def body_size(self) -> int:
        return len(self.body or b"")

    @classmethod
    def from_httpx(cls, response: httpx.Response, elapsed_ms: float = 0.0) -> "ReplayResponse":
        return cls(response.status_code, dict(response.headers), response.content, elapsed_ms, str(response.url))


class PayloadInjector:
    def build(self, endpoint: Any, param: dict[str, Any], payload: str) -> ReplayRequest:
        request = ReplayRequest(
            method=getattr(endpoint, "method", "GET"),
            url=getattr(endpoint, "sample_url", getattr(endpoint, "url_template", "")),
            headers=dict(getattr(endpoint, "request_headers", {}) or {}),
            body=_body_from_endpoint(endpoint),
        ).without_headers(_REPLAY_STRIP_HEADERS)
        location = param.get("location")
        name = param.get("name") or param.get("path")
        if location == "query":
            return request.with_query_param(name, payload)
        if location in {"form", "body", "form_body"}:
            return request.with_body_param(name, payload)
        if location == "json_body":
            return request.with_json_body_param(param.get("path") or name, payload)
        if location == "header":
            headers = request.sanitized_headers(); headers[name] = payload
            return replace(request, headers=headers)
        return request


def _body_from_endpoint(endpoint: Any) -> str | None:
    body = getattr(endpoint, "request_body", None)
    if body is None:
        return None
    if isinstance(body, dict):
        if "raw" in body:
            return body.get("raw")
        if "json" in body:
            return json.dumps(body.get("json"), separators=(",", ":"))
        if "form" in body:
            return urlencode(body.get("form") or {})
        return json.dumps(body, separators=(",", ":"))
    return str(body)


class ReplayEngine:
    def __init__(self, session: Any = None, *, rate_limiter: RateLimiter | None = None, timeout: float = 15.0, max_retries: int = 2):
        self.session = session
        self.rate_limiter = rate_limiter or RateLimiter()
        self.timeout = timeout
        self.max_retries = max_retries
        self.injector = PayloadInjector()
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "ReplayEngine":
        self._client = httpx.AsyncClient(timeout=self.timeout, follow_redirects=False, verify=False)
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self._client:
            await self._client.aclose()
        self._client = None

    async def replay(self, request: ReplayRequest) -> ReplayResponse:
        async with await self.rate_limiter.acquire(request.url):
            return await self._send_with_retries(request.without_headers(_REPLAY_STRIP_HEADERS))

    async def baseline(self, endpoint: Any) -> ReplayResponse:
        request = ReplayRequest(
            method=getattr(endpoint, "method", "GET"),
            url=getattr(endpoint, "sample_url", getattr(endpoint, "url_template", "")),
            headers=dict(getattr(endpoint, "request_headers", {}) or {}),
            body=_body_from_endpoint(endpoint),
        )
        return await self.replay(request)

    async def inject(self, endpoint: Any, param: dict[str, Any], payload: str) -> ReplayResponse:
        return await self.replay(self.injector.build(endpoint, param, payload))

    async def _send_with_retries(self, request: ReplayRequest) -> ReplayResponse:
        attempt = 0
        while True:
            response = await self._send_once(request)
            if response.status_code not in {429, 503} or attempt >= self.max_retries:
                return response
            delay = self._retry_delay(response, attempt)
            await asyncio.sleep(delay)
            attempt += 1

    async def _send_once(self, request: ReplayRequest) -> ReplayResponse:
        client = self._client or httpx.AsyncClient(timeout=self.timeout, follow_redirects=False, verify=False)
        close_client = self._client is None
        headers = request.sanitized_headers()
        session_kwargs = self.session.to_httpx_kwargs() if hasattr(self.session, "to_httpx_kwargs") else {}
        headers.update(session_kwargs.pop("headers", {}) or {})
        try:
            started = asyncio.get_running_loop().time()
            response = await client.request(request.method, request.url, headers=headers, content=request.body, **session_kwargs)
            elapsed = (asyncio.get_running_loop().time() - started) * 1000
            return ReplayResponse.from_httpx(response, elapsed)
        finally:
            if close_client:
                await client.aclose()

    def _retry_delay(self, response: ReplayResponse, attempt: int) -> float:
        retry_after = response.headers.get("Retry-After") or response.headers.get("retry-after")
        if retry_after:
            try:
                return max(0.0, float(retry_after))
            except ValueError:
                try:
                    date = parsedate_to_datetime(retry_after)
                    if date.tzinfo is None:
                        date = date.replace(tzinfo=timezone.utc)
                    return max(0.0, (date - datetime.now(timezone.utc)).total_seconds())
                except Exception:
                    pass
        return min(8.0, 0.5 * (2 ** attempt))
