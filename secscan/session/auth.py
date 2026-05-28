from __future__ import annotations

import importlib.util
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from playwright.async_api import async_playwright

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


@dataclass
class Session:
    cookies: list[dict[str, Any]] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    storage_state: dict[str, Any] = field(default_factory=dict)
    expires_at: datetime | None = None

    def is_expired(self) -> bool:
        return bool(self.expires_at and datetime.now(timezone.utc) >= self.expires_at)

    def to_httpx_kwargs(self) -> dict[str, Any]:
        cookies = {}
        for cookie in self.cookies:
            if isinstance(cookie, dict) and "name" in cookie:
                cookies[cookie["name"]] = cookie.get("value", "")
        return {"cookies": cookies, "headers": dict(self.headers or {})}


def _load_auth_module(path: Path):
    spec = importlib.util.spec_from_file_location("secscan_target_auth", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load auth script {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "authenticate"):
        raise RuntimeError(f"{path} must define async authenticate(page, config)")
    return module


async def bootstrap_session(config: Any, target_dir: Path | None = None) -> Session:
    target_name = getattr(getattr(config, "target", None), "name", "")
    script = getattr(getattr(config, "auth", None), "script", "auth_script.py")
    target_dir = target_dir or Path("targets") / target_name
    module = _load_auth_module(target_dir / script)
    expiry_minutes = getattr(getattr(config, "auth", None), "session_expiry_minutes", 30)

    captured_auth_headers: list[str] = []
    captured_login_bodies: list[str] = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()

        async def record_response(response):
            try:
                ctype = response.headers.get("content-type", "")
                if "json" in ctype or "text" in ctype:
                    text = await response.text()
                    if "token" in text.lower() or JWT_RE.search(text):
                        captured_login_bodies.append(text[:20000])
            except Exception:
                return

        async def record_request(request):
            auth = request.headers.get("authorization")
            if auth and auth.lower().startswith("bearer "):
                captured_auth_headers.append(auth)

        page.on("request", record_request)
        page.on("response", record_response)
        await module.authenticate(page, config)
        storage_state = await context.storage_state()
        cookies = await context.cookies()
        headers: dict[str, str] = {}
        token = _select_bearer_token(captured_auth_headers, cookies, captured_login_bodies, storage_state)
        if token:
            headers["Authorization"] = f"Bearer {token}"
        await browser.close()

    return Session(cookies=cookies, headers=headers, storage_state=storage_state, expires_at=datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes))


def _select_bearer_token(auth_headers: list[str], cookies: list[dict[str, Any]], bodies: list[str], storage_state: dict[str, Any]) -> str | None:
    for header in reversed(auth_headers):
        match = re.search(r"bearer\s+(.+)", header, re.I)
        if match and JWT_RE.search(match.group(1)):
            return match.group(1).strip()
    for cookie in cookies:
        value = str(cookie.get("value", ""))
        if JWT_RE.fullmatch(value):
            return value
    for body in reversed(bodies):
        token = _find_token_field(body)
        if token:
            return token
    for origin in storage_state.get("origins", []) if isinstance(storage_state, dict) else []:
        for bucket in (origin.get("localStorage", []), origin.get("sessionStorage", [])):
            for item in bucket:
                value = str(item.get("value", ""))
                match = JWT_RE.search(value)
                if match:
                    return match.group(0)
    return None


def _find_token_field(text: str) -> str | None:
    match = JWT_RE.search(text or "")
    if match:
        return match.group(0)
    try:
        data = json.loads(text)
    except Exception:
        return None
    stack = [data]
    while stack:
        value = stack.pop()
        if isinstance(value, dict):
            for key, item in value.items():
                if "token" in str(key).lower() and isinstance(item, str):
                    return item
                stack.append(item)
        elif isinstance(value, list):
            stack.extend(value)
    return None
