from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from secscan.checks.base import Endpoint
from .har_parser import HarEntry

_AUTH_NAME_RE = re.compile(r"(authorization|auth|token|csrf|xsrf|session|cookie|api[-_]?key|jwt)", re.I)
_JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
_ID_SEGMENT_RE = re.compile(r"^[0-9a-f]{8,}$", re.I)


def normalize_entries(entries: list[HarEntry], base_url: str | None = None) -> list[Endpoint]:
    grouped: dict[tuple[str, str], list[HarEntry]] = defaultdict(list)
    for entry in entries:
        key = (entry.method.upper(), _template_url(entry.url))
        grouped[key].append(entry)

    endpoints: list[Endpoint] = []
    for (method, template), group in grouped.items():
        sample = group[0]
        params = _extract_params(group)
        request_body = _request_body(sample)
        endpoints.append(Endpoint(
            method=method,
            url_template=template,
            sample_url=sample.url,
            request_body=request_body,
            request_headers=sample.headers,
            mutable_params=params,
        ))
    return endpoints


def _template_url(url: str) -> str:
    parts = urlsplit(url)
    segments = []
    for segment in parts.path.split("/"):
        if not segment:
            segments.append(segment)
        elif segment.isdigit() or _ID_SEGMENT_RE.match(segment):
            segments.append("{id}")
        else:
            segments.append(segment)
    return urlunsplit((parts.scheme, parts.netloc, "/".join(segments), "", ""))


def _extract_params(group: list[HarEntry]) -> list[dict[str, Any]]:
    observed: dict[tuple[str, str], list[str]] = defaultdict(list)
    paths: dict[tuple[str, str], str] = {}
    for entry in group:
        for name, value in entry.query_params.items():
            key = ("query", name); observed[key].append(value); paths[key] = name
        mime = (entry.post_data_mime or "").split(";")[0].strip().lower()
        body = entry.post_data_text or ""
        if mime == "application/json" or (body.strip().startswith("{") or body.strip().startswith("[")):
            try:
                data = json.loads(body) if body else {}
            except Exception:
                data = {}
            for path, value in _walk_json(data):
                key = ("json_body", path); observed[key].append("" if value is None else str(value)); paths[key] = path
        elif mime == "application/x-www-form-urlencoded" or "=" in body:
            for name, value in parse_qsl(body, keep_blank_values=True):
                key = ("form", name); observed[key].append(value); paths[key] = name
    params = []
    for (location, name), values in observed.items():
        sample = next((v for v in values if v is not None), "")
        params.append({
            "name": name.split(".")[-1],
            "path": paths[(location, name)],
            "location": location,
            "sample_value": sample,
            "classification": _classify_param(name, values),
        })
    return params


def _walk_json(value: Any, prefix: str = ""):
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            yield from _walk_json(item, path)
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            path = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
            yield from _walk_json(item, path)
    else:
        if prefix:
            yield prefix, value


def _classify_param(name: str, values: list[str]) -> str:
    sample = next((str(v) for v in values if v is not None), "")
    if _AUTH_NAME_RE.search(name) or _JWT_RE.match(sample) or (_entropy(sample) > 4.0 and len(sample) > 20):
        return "auth_bound"
    return "mutable"


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    freq = {ch: value.count(ch) for ch in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _request_body(entry: HarEntry) -> dict[str, Any] | None:
    if not entry.post_data_text:
        return None
    mime = (entry.post_data_mime or "").split(";")[0].strip().lower()
    text = entry.post_data_text
    if mime == "application/json" or text.strip().startswith(("{", "[")):
        try:
            return {"raw": text, "json": json.loads(text), "mime": "application/json"}
        except Exception:
            return {"raw": text, "mime": mime}
    if mime == "application/x-www-form-urlencoded" or "=" in text:
        return {"raw": text, "form": dict(parse_qsl(text, keep_blank_values=True)), "mime": "application/x-www-form-urlencoded"}
    return {"raw": text, "mime": mime}
