from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit

from playwright.async_api import async_playwright

from secscan.crawler.blocklist import BlocklistChecker
from secscan.ingest.har_parser import HarEntry
from secscan.replay.ratelimit import RateLimiter

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
    """Phase 1/2 crawler: base navigation, request capture, DOM surface extraction."""

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
        self.last_dom_surface = DOMSurface()

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
            self.last_dom_surface = await _extract_dom_surface(page, base_url)
            _LOG.info(
                "DOM extraction: %s links, %s forms, %s buttons found.",
                len(self.last_dom_surface.links),
                len(self.last_dom_surface.forms),
                len(self.last_dom_surface.buttons),
            )
            await _interact_with_forms(page, self.last_dom_surface.forms, self.blocklist, self.rate_limiter)
            await browser.close()

        return captured


async def _extract_dom_surface(page: Any, base_url: str) -> DOMSurface:
    raw = await page.evaluate(_DOM_EXTRACTION_SCRIPT, base_url)
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
  const buttonNodes = Array.from(document.querySelectorAll('button, input[type="submit"], [role="button"], [routerLink], [data-href]'));
  const buttons = buttonNodes.map((button) => ({
    text: textOf(button),
    selector: selectorFor(button),
    form_selector: selectorFor(button.closest('form')),
    route_hint: button.getAttribute('routerLink') || button.getAttribute('data-href') || button.getAttribute('href') || '',
  }));
  return { links, forms, buttons };
}
"""
