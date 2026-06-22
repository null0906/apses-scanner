from __future__ import annotations

import asyncio
import logging
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit
from uuid import uuid4

import httpx
from playwright.async_api import async_playwright

from secscan.crawler.blocklist import BlocklistChecker
from secscan.ingest.har_parser import HarEntry
from secscan.replay.ratelimit import RateLimiter
from secscan.utils.http import SPAShellFingerprint, fingerprint_spa_shell, matches_spa_shell

EndpointRecord = HarEntry

_LOG = logging.getLogger(__name__)
_CAPTURE_TYPES = {"xhr", "fetch"}


@dataclass(frozen=True)
class FormFieldSpec:
    name: str
    type: str
    value: str
    selector: str


@dataclass(frozen=True)
class FormSpec:
    action: str
    method: str
    fields: list[FormFieldSpec] = field(default_factory=list)
    selector: str = ""
    submit_selector: str = ""
    submit_text: str = ""


@dataclass(frozen=True)
class ButtonSpec:
    text: str
    selector: str
    form_selector: str = ""
    route_hint: str = ""


@dataclass(frozen=True)
class DOMSurface:
    links: list[str] = field(default_factory=list)
    forms: list[FormSpec] = field(default_factory=list)
    buttons: list[ButtonSpec] = field(default_factory=list)


class CrawlerEngine:
    """Authenticated browser crawler with bounded breadth-first navigation."""

    def __init__(self, config: Any, session: Any):
        self.config = config
        self.session = session
        scan = getattr(config, "scan", None)
        self.rate_limiter = RateLimiter(
            getattr(scan, "max_concurrency", 2),
            getattr(scan, "rate_limit_rps", 2),
        )
        crawler = getattr(config, "crawler", None)
        self.blocklist = BlocklistChecker(
            extra_patterns=list(getattr(crawler, "blocklist_extra", []) or []),
            override_defaults=bool(getattr(crawler, "blocklist_override", False)),
        )
        self.max_depth = int(getattr(crawler, "max_depth", 3))
        self.max_pages = int(getattr(crawler, "max_pages", 50))
        self.max_time_seconds = int(getattr(crawler, "max_time_seconds", 1800))
        self.wordlist_path = str(getattr(crawler, "wordlist_path", "") or "")
        self.forced_browsing_enabled = bool(getattr(crawler, "forced_browsing_enabled", crawler is not None))
        self.last_dom_surface = DOMSurface()
        self.visited_urls: set[str] = set()
        self.max_depth_reached = 0
        self.last_summary = ""
        self.last_forced_browsing_summary = ""

    async def crawl(self, target_name: str) -> list[EndpointRecord]:
        base_url = getattr(getattr(self.config, "target", None), "base_url", "")
        if not base_url:
            raise ValueError(f"Target {target_name} has no configured base_url")

        captured = _session_request_entries(getattr(self.session, "captured_requests", []) or [], base_url)
        base_host = _host(base_url)
        queue: deque[tuple[str, int]] = deque()
        queued: set[str] = set()
        self.visited_urls = set()
        self.max_depth_reached = 0
        self.last_summary = ""
        self.last_forced_browsing_summary = ""
        _enqueue_url(queue, queued, self.visited_urls, base_url, 0, base_url, self.max_depth)
        stop_reason = "queue_empty"

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            try:
                context = await browser.new_context(
                    ignore_https_errors=True,
                    extra_http_headers=dict(getattr(self.session, "headers", {}) or {}),
                )
                await _add_session_cookies(context, getattr(self.session, "cookies", []) or [], base_url)
                page = await context.new_page()

                navigation_url = base_url.rstrip("/")

                async def rate_limited_route(route):
                    request_url = route.request.url
                    if route.request.resource_type == "document" or request_url.rstrip("/") == navigation_url:
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
                try:
                    async with asyncio.timeout(self.max_time_seconds):
                        while queue:
                            if len(self.visited_urls) >= self.max_pages:
                                stop_reason = "max_pages"
                                break
                            url, depth = queue.popleft()
                            key = _crawl_key(url, base_url)
                            queued.discard(key)
                            if key in self.visited_urls or not _in_scope(url, base_url):
                                continue
                            self.visited_urls.add(key)
                            self.max_depth_reached = max(self.max_depth_reached, depth)
                            previous_url = getattr(page, "url", base_url) or base_url
                            if not await _navigate_in_scope(page, url, previous_url, base_url, self.rate_limiter):
                                continue
                            self.last_dom_surface = await _extract_dom_surface(page, base_url)
                            _LOG.info(
                                "DOM extraction: %s links, %s forms, %s buttons found.",
                                len(self.last_dom_surface.links),
                                len(self.last_dom_surface.forms),
                                len(self.last_dom_surface.buttons),
                            )
                            await _interact_with_forms(page, self.last_dom_surface.forms, self.blocklist, self.rate_limiter)
                            for link in self.last_dom_surface.links:
                                _enqueue_url(queue, queued, self.visited_urls, link, depth + 1, base_url, self.max_depth)
                            await _follow_route_hint_buttons(
                                page,
                                self.last_dom_surface.buttons,
                                url,
                                depth,
                                base_url,
                                queue,
                                queued,
                                self.visited_urls,
                                self.max_depth,
                                self.blocklist,
                                self.rate_limiter,
                            )
                except TimeoutError:
                    stop_reason = "max_time"
                    _LOG.warning("Crawler stopped after reaching max_time_seconds=%s.", self.max_time_seconds)
            finally:
                await browser.close()

        if self.forced_browsing_enabled:
            wordlist = _load_wordlist(self.wordlist_path)
            discoveries = await _forced_browse(base_url, wordlist, self.session, self.rate_limiter)
            captured.extend(discoveries)
            self.last_forced_browsing_summary = f"Forced browsing: {len(wordlist)} paths probed, {len(discoveries)} discovered."
            _LOG.info(self.last_forced_browsing_summary)

        self.last_summary = (
            f"Crawl complete: {len(self.visited_urls)} pages visited, {len(captured)} endpoints captured, "
            f"depth {self.max_depth_reached} reached, stopped by {stop_reason}."
        )
        _LOG.info(self.last_summary)
        return captured


async def _extract_dom_surface(page: Any, base_url: str) -> DOMSurface:
    raw = None
    for attempt in range(2):
        try:
            raw = await page.evaluate(_DOM_EXTRACTION_SCRIPT, base_url)
            break
        except Exception as exc:
            if attempt:
                _LOG.info("Skipping DOM extraction after navigation race: %s", exc)
                return DOMSurface()
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=3000)
            except Exception:
                pass
    raw = raw or {}
    return DOMSurface(
        links=_same_domain_urls(raw.get("links", []), base_url),
        forms=[_form_from_raw(item, base_url) for item in raw.get("forms", []) or []],
        buttons=[_button_from_raw(item) for item in raw.get("buttons", []) or []],
    )


def _form_from_raw(item: dict[str, Any], base_url: str) -> FormSpec:
    fields = [
        FormFieldSpec(
            name=str(field.get("name", "")),
            type=str(field.get("type", "text") or "text").lower(),
            value=str(field.get("value", "")),
            selector=str(field.get("selector", "")),
        )
        for field in item.get("fields", []) or []
        if field.get("selector")
    ]
    return FormSpec(
        action=_normalize_url(str(item.get("action", "") or base_url), base_url),
        method=str(item.get("method", "GET") or "GET").upper(),
        fields=fields,
        selector=str(item.get("selector", "")),
        submit_selector=str(item.get("submit_selector", "")),
        submit_text=str(item.get("submit_text", "")),
    )


def _button_from_raw(item: dict[str, Any]) -> ButtonSpec:
    return ButtonSpec(
        text=str(item.get("text", "")),
        selector=str(item.get("selector", "")),
        form_selector=str(item.get("form_selector", "")),
        route_hint=str(item.get("route_hint", "")),
    )


async def _interact_with_forms(page: Any, forms: list[FormSpec], blocklist: BlocklistChecker, rate_limiter: RateLimiter) -> None:
    for form in forms:
        if blocklist.blocks_form(form):
            _LOG.warning("Skipping form %s - matches destructive pattern.", form.action)
            continue
        filled = False
        filled_selectors: list[str] = []
        for field in form.fields:
            value = _test_value_for_field(field.type)
            if value is None or not field.selector:
                continue
            try:
                await _fill_field(page, field.selector, value)
            except Exception as exc:
                _LOG.info("Skipping non-interactable field %s: %s", field.selector, exc)
                continue
            filled = True
            filled_selectors.append(field.selector)
        if not filled:
            continue
        async with await rate_limiter.acquire(form.action):
            if form.submit_selector:
                await page.click(form.submit_selector)
            elif filled_selectors:
                await page.press(filled_selectors[0], "Enter")
        try:
            await page.wait_for_load_state("networkidle", timeout=3000)
        except Exception:
            pass


async def _fill_field(page: Any, selector: str, value: str) -> None:
    try:
        await page.fill(selector, value, timeout=1500)
    except TypeError:
        await page.fill(selector, value)


async def _navigate_in_scope(page: Any, url: str, previous_url: str, base_url: str, rate_limiter: RateLimiter) -> bool:
    if not _in_scope(url, base_url):
        _LOG.debug("Dropping out-of-scope crawler navigation: %s", url)
        return False
    try:
        async with await rate_limiter.acquire(url):
            await _goto_page(page, url)
    except Exception as exc:
        _LOG.info("Navigation did not reach networkidle for %s: %s", url, exc)
    actual_url = getattr(page, "url", url) or url
    if _in_scope(actual_url, base_url):
        return True
    _LOG.warning("External redirect blocked: %s", actual_url)
    if _in_scope(previous_url, base_url):
        async with await rate_limiter.acquire(previous_url):
            await page.goto(previous_url, wait_until="networkidle")
    return False


async def _follow_route_hint_buttons(
    page: Any,
    buttons: list[ButtonSpec],
    current_url: str,
    depth: int,
    base_url: str,
    queue: deque[tuple[str, int]],
    queued: set[str],
    visited: set[str],
    max_depth: int,
    blocklist: BlocklistChecker,
    rate_limiter: RateLimiter,
) -> None:
    for button in buttons:
        if not button.route_hint or not button.selector:
            continue
        if blocklist.blocks_button_text(button.text):
            _LOG.warning("Skipping route button %s - matches destructive pattern.", button.text)
            continue
        route_url = _normalize_url(button.route_hint, current_url)
        if not _in_scope(route_url, base_url):
            _LOG.debug("Dropping out-of-scope route hint: %s", route_url)
            continue
        try:
            async with await rate_limiter.acquire(route_url):
                await _click_button(page, button.selector)
            try:
                await page.wait_for_load_state("networkidle", timeout=3000)
            except Exception:
                pass
        except Exception as exc:
            _LOG.info("Skipping non-interactable route button %s: %s", button.selector, exc)
            continue

        actual_url = getattr(page, "url", route_url) or route_url
        if not _in_scope(actual_url, base_url):
            _LOG.warning("External redirect blocked: %s", actual_url)
            await _return_to_url(page, current_url, base_url, rate_limiter)
            continue

        surface = await _extract_dom_surface(page, base_url)
        await _interact_with_forms(page, surface.forms, blocklist, rate_limiter)
        _enqueue_url(queue, queued, visited, actual_url, depth + 1, base_url, max_depth)
        for link in surface.links:
            _enqueue_url(queue, queued, visited, link, depth + 2, base_url, max_depth)
        if _crawl_key(actual_url, base_url) != _crawl_key(current_url, base_url):
            await _return_to_url(page, current_url, base_url, rate_limiter)


async def _click_button(page: Any, selector: str) -> None:
    try:
        await page.click(selector, timeout=3000)
    except TypeError:
        await page.click(selector)


async def _return_to_url(page: Any, url: str, base_url: str, rate_limiter: RateLimiter) -> None:
    if not _in_scope(url, base_url):
        return
    try:
        async with await rate_limiter.acquire(url):
            await _goto_page(page, url)
    except Exception as exc:
        _LOG.info("Return navigation did not reach networkidle for %s: %s", url, exc)


async def _goto_page(page: Any, url: str) -> None:
    try:
        await page.goto(url, wait_until="networkidle", timeout=5000)
    except TypeError:
        await page.goto(url, wait_until="networkidle")


def _test_value_for_field(field_type: str) -> str | None:
    normalized = (field_type or "text").lower()
    if normalized in {"password", "hidden", "file"}:
        return None
    if normalized in {"text", "search"}:
        return "secscan_test"
    if normalized == "email":
        return "test@secscan.internal"
    if normalized == "number":
        return "1"
    return "secscan_test"


def _same_domain_urls(urls: list[str], base_url: str) -> list[str]:
    base_host = _host(base_url)
    seen = set()
    kept = []
    for url in urls or []:
        normalized = _normalize_url(str(url), base_url)
        if _host(normalized) != base_host or normalized in seen:
            continue
        seen.add(normalized)
        kept.append(normalized)
    return kept


def _enqueue_url(
    queue: deque[tuple[str, int]],
    queued: set[str],
    visited: set[str],
    candidate: str,
    depth: int,
    base_url: str,
    max_depth: int,
) -> bool:
    normalized = _normalize_url(candidate, base_url)
    if depth > max_depth:
        return False
    if not _in_scope(normalized, base_url):
        _LOG.debug("Dropping out-of-scope crawler navigation: %s", normalized)
        return False
    key = _crawl_key(normalized, base_url)
    if key in visited or key in queued:
        return False
    queue.append((normalized, depth))
    queued.add(key)
    return True


def _crawl_key(url: str, base_url: str) -> str:
    normalized = _normalize_url(url, base_url)
    parts = urlsplit(normalized)
    if parts.fragment.startswith("/"):
        route = urlsplit(parts.fragment)
        return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), route.path or "/", route.query, ""))
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", parts.query, ""))


def _in_scope(url: str, base_url: str) -> bool:
    return _host(_normalize_url(url, base_url)) == _host(base_url)


def _normalize_url(url: str, base_url: str) -> str:
    return urljoin(base_url, url or base_url)


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


def _session_request_entries(requests: list[dict[str, Any]], base_url: str) -> list[HarEntry]:
    entries = []
    for request in requests:
        url = str(request.get("url", ""))
        if not url or not _in_scope(url, base_url):
            continue
        headers = {str(k): str(v) for k, v in (request.get("headers", {}) or {}).items()}
        entries.append(HarEntry(
            method=str(request.get("method", "GET")).upper(),
            url=url,
            headers=headers,
            query_params={k: v for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True)},
            post_data_mime=_content_type(headers),
            post_data_text=str(request.get("post_data", "") or ""),
        ))
    return entries


def _load_wordlist(override_path: str = "") -> list[str]:
    path = Path(override_path).expanduser() if override_path else Path(__file__).with_name("wordlist.txt")
    return [
        line if line.startswith("/") else f"/{line}"
        for raw in path.read_text(encoding="utf-8").splitlines()
        if (line := raw.strip()) and not line.startswith("#")
    ]


async def _forced_browse(
    base_url: str,
    paths: list[str],
    session: Any,
    rate_limiter: RateLimiter,
    client: Any | None = None,
) -> list[HarEntry]:
    discoveries: list[HarEntry] = []
    owns_client = client is None
    if client is None:
        session_kwargs = session.to_httpx_kwargs() if hasattr(session, "to_httpx_kwargs") else {}
        client = httpx.AsyncClient(timeout=10, follow_redirects=False, verify=False, **session_kwargs)
    try:
        shell = await _spa_shell_baseline(base_url, client, rate_limiter)
        for path in paths:
            url = urljoin(f"{base_url.rstrip('/')}/", path.lstrip("/"))
            try:
                async with await rate_limiter.acquire(url):
                    response = await client.get(url)
            except Exception as exc:
                _LOG.info("Forced-browsing probe failed for %s: %s", url, exc)
                continue
            if 200 <= response.status_code < 300 or 500 <= response.status_code < 600:
                if shell and matches_spa_shell(shell, response.headers, response.text):
                    continue
                discoveries.append(HarEntry(
                    method="GET",
                    url=url,
                    headers={},
                    query_params={},
                    response_status=response.status_code,
                    response_headers={str(k): str(v) for k, v in response.headers.items()},
                    response_body=response.text,
                ))
    finally:
        if owns_client:
            await client.aclose()
    return discoveries


async def _spa_shell_baseline(base_url: str, client: Any, rate_limiter: RateLimiter) -> SPAShellFingerprint | None:
    token = uuid4().hex
    url = urljoin(f"{base_url.rstrip('/')}/", f"secscan-nonexistent-probe-{token}")
    try:
        async with await rate_limiter.acquire(url):
            response = await client.get(url)
    except Exception as exc:
        _LOG.info("SPA-shell baseline probe failed for %s: %s", url, exc)
        return None
    return fingerprint_spa_shell(response.headers, response.text)


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


_DOM_EXTRACTION_SCRIPT = """
(baseUrl) => {
  const absolute = (value) => {
    try { return new URL(value || baseUrl, baseUrl).href; } catch { return ''; }
  };
  const cssEscape = (value) => {
    if (window.CSS && CSS.escape) return CSS.escape(value);
    return String(value).replace(/[^a-zA-Z0-9_-]/g, '\\$&');
  };
  const selectorFor = (el) => {
    if (!el) return '';
    if (el.id) return `#${cssEscape(el.id)}`;
    const parts = [];
    let cur = el;
    while (cur && cur.nodeType === Node.ELEMENT_NODE && cur !== document.body) {
      let part = cur.tagName.toLowerCase();
      if (cur.getAttribute('name')) part += `[name="${cssEscape(cur.getAttribute('name'))}"]`;
      else {
        const parent = cur.parentElement;
        if (parent) {
          const siblings = Array.from(parent.children).filter((child) => child.tagName === cur.tagName);
          if (siblings.length > 1) part += `:nth-of-type(${siblings.indexOf(cur) + 1})`;
        }
      }
      parts.unshift(part);
      cur = cur.parentElement;
    }
    return parts.length ? parts.join(' > ') : el.tagName.toLowerCase();
  };
  const textOf = (el) => (el.innerText || el.value || el.getAttribute('aria-label') || '').trim();
  const isInteractable = (el) => {
    const type = (el.getAttribute('type') || '').toLowerCase();
    if (el.disabled || el.getAttribute('aria-disabled') === 'true') return false;
    if (['hidden', 'file', 'submit', 'button'].includes(type)) return false;
    const rect = el.getBoundingClientRect();
    return !!(rect.width || rect.height);
  };
  const links = Array.from(document.querySelectorAll('a[href]')).map((a) => absolute(a.getAttribute('href'))).filter(Boolean);
  const submitFor = (form) => {
    const inside = form.querySelector('button[type="submit"], input[type="submit"], button:not([type]), [role="button"]');
    if (inside) return inside;
    const formId = form.getAttribute('id') || form.getAttribute('name');
    if (!formId) return null;
    const escaped = cssEscape(formId);
    return document.querySelector(`button[form="${escaped}"], input[type="submit"][form="${escaped}"], [role="button"][form="${escaped}"]`);
  };
  const fieldFrom = (field) => ({
    name: field.getAttribute('name') || field.getAttribute('formcontrolname') || field.id || '',
    type: (field.getAttribute('type') || field.tagName.toLowerCase() || 'text').toLowerCase(),
    value: field.value || field.getAttribute('value') || '',
    selector: selectorFor(field),
  });
  const forms = Array.from(document.querySelectorAll('form')).map((form) => {
    const submit = submitFor(form);
    return {
      action: absolute(form.getAttribute('action') || window.location.href),
      method: (form.getAttribute('method') || 'GET').toUpperCase(),
      selector: selectorFor(form),
      submit_selector: selectorFor(submit),
      submit_text: submit ? textOf(submit) : '',
      fields: Array.from(form.querySelectorAll('input, textarea, select')).filter(isInteractable).map(fieldFrom),
    };
  });
  const standaloneFields = Array.from(document.querySelectorAll('input, textarea, select')).filter((field) => {
    if (field.closest('form')) return false;
    if (!isInteractable(field)) return false;
    const type = (field.getAttribute('type') || field.tagName.toLowerCase() || 'text').toLowerCase();
    return !['password', 'hidden', 'file', 'checkbox', 'radio', 'submit', 'button'].includes(type);
  });
  forms.push(...standaloneFields.map((field) => ({
    action: absolute(window.location.href),
    method: 'GET',
    selector: selectorFor(field.parentElement || field),
    submit_selector: '',
    submit_text: '',
    fields: [fieldFrom(field)],
  })));
  const routeHintOf = (button) => {
    const direct = button.getAttribute('routerLink') || button.getAttribute('data-href') || button.getAttribute('href');
    if (direct) return direct;
    const onclick = button.getAttribute('onclick') || '';
    const match = onclick.match(/(?:window\\.)?location(?:\\.href)?\\s*=\\s*['"]([^'"]+)['"]/i)
      || onclick.match(/window\\.open\\(\\s*['"]([^'"]+)['"]/i);
    return match ? match[1] : '';
  };
  const buttonNodes = Array.from(document.querySelectorAll('button, input[type="submit"], [role="button"], [routerLink], [data-href], [onclick]'));
  const buttons = buttonNodes.map((button) => ({
    text: textOf(button),
    selector: selectorFor(button),
    form_selector: selectorFor(button.closest('form')),
    route_hint: routeHintOf(button),
  }));
  return { links, forms, buttons };
}
"""
