from __future__ import annotations

import logging
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from playwright.async_api import async_playwright

from secscan.ingest.har_parser import HarEntry
from secscan.replay.ratelimit import RateLimiter

EndpointRecord = HarEntry

_LOG = logging.getLogger(__name__)
_CAPTURE_TYPES = {"xhr", "fetch"}


class CrawlerEngine:
    """Phase 1 crawler: navigate base URL and capture same-domain XHR/fetch."""

    def __init__(self, config: Any, session: Any):
        self.config = config
        self.session = session
        scan = getattr(config, "scan", None)
        self.rate_limiter = RateLimiter(
            getattr(scan, "max_concurrency", 2),
            getattr(scan, "rate_limit_rps", 2),
        )

    async def crawl(self, target_name: str) -> list[EndpointRecord]:
        base_url = getattr(getattr(self.config, "target", None), "base_url", "")
        if not base_url:
            raise ValueError(f"Target {target_name} has no configured base_url")

        captured: list[EndpointRecord] = []
        base_host = _host(base_url)

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                ignore_https_errors=True,
                extra_http_headers=dict(getattr(self.session, "headers", {}) or {}),
            )
            await _add_session_cookies(context, getattr(self.session, "cookies", []) or [], base_url)
            page = await context.new_page()

            navigation_url = base_url.rstrip("/")

            async def rate_limited_route(route):
                request_url = route.request.url
                if request_url.rstrip("/") == navigation_url:
                    await route.continue_()
                    return
                async with await self.rate_limiter.acquire(request_url):
                    await route.continue_()

            async def capture_request(request):
                if request.resource_type not in _CAPTURE_TYPES:
                    return
                if _host(request.url) != base_host:
                    _LOG.debug("Dropping out-of-scope crawler request: %s", request.url)
                    return
                captured.append(_request_to_entry(request))

            await page.route("**/*", rate_limited_route)
            page.on("request", capture_request)
            async with await self.rate_limiter.acquire(base_url):
                await page.goto(base_url, wait_until="networkidle")
            await browser.close()

        return captured


def _host(url: str) -> str:
    return urlsplit(url).netloc.lower()


def _request_to_entry(request) -> HarEntry:
    post_data = request.post_data or ""
    mime = _content_type(request.headers)
    return HarEntry(
        method=request.method.upper(),
        url=request.url,
        headers={str(k): str(v) for k, v in (request.headers or {}).items()},
        query_params={k: v for k, v in parse_qsl(urlsplit(request.url).query, keep_blank_values=True)},
        post_data_mime=mime,
        post_data_text=post_data,
    )


def _content_type(headers: dict[str, str]) -> str:
    for key, value in (headers or {}).items():
        if key.lower() == "content-type":
            return value
    return ""


async def _add_session_cookies(context, cookies: list[dict[str, Any]], base_url: str) -> None:
    prepared = []
    for cookie in cookies:
        if not isinstance(cookie, dict) or not cookie.get("name"):
            continue
        item = dict(cookie)
        if "url" not in item and "domain" not in item:
            item["url"] = base_url
        prepared.append(item)
    if prepared:
        await context.add_cookies(prepared)
