from __future__ import annotations

import json
from typing import AsyncIterator

from .base import Check, Endpoint, Finding
from .common import injectable_params, more_access, poc
from .payloads.sqli import BOOLEAN_PAIRS, ERROR_BASED, ERROR_SIGNATURES, NOSQL, TIME_BASED, UNION_BASED


class SQLiCheck(Check):
    name = "sqli"
    description = "SQL injection checks for captured mutable parameters."

    async def run(self, endpoint: Endpoint, session, replay) -> AsyncIterator[Finding]:
        params = injectable_params(endpoint)
        if not params:
            return
        baseline = await replay.baseline(endpoint)
        seen: set[tuple[str, str]] = set()
        for param in params:
            async for finding in self._error_based(endpoint, replay, baseline, param):
                key = (finding.evidence.get("sub_technique", ""), param.get("path") or param.get("name"))
                if key not in seen:
                    seen.add(key); yield finding
            async for finding in self._boolean_based(endpoint, replay, baseline, param):
                key = (finding.evidence.get("sub_technique", ""), param.get("path") or param.get("name"))
                if key not in seen:
                    seen.add(key); yield finding
            async for finding in self._nosql(endpoint, replay, baseline, param):
                key = (finding.evidence.get("sub_technique", ""), param.get("path") or param.get("name"))
                if key not in seen:
                    seen.add(key); yield finding

    async def _error_based(self, endpoint, replay, baseline, param):
        for payload in ERROR_BASED + UNION_BASED:
            resp = await replay.inject(endpoint, param, payload)
            text = resp.body_text.lower()
            signature = next((sig for sig in ERROR_SIGNATURES if sig.lower() in text), None)
            broke_query = baseline.status_code < 500 and 500 <= resp.status_code < 600
            if broke_query or signature:
                yield _finding(endpoint, "error_based", param, payload, "high", "SQL injection error signal", {
                    "sub_technique": "error_based", "param": param, "payload": payload,
                    "baseline_status": baseline.status_code, "status": resp.status_code,
                    "signature": signature, "status_broke_query": broke_query,
                    "response_excerpt": resp.body_text[:500],
                })
                return

    async def _boolean_based(self, endpoint, replay, baseline, param):
        for true_payload, false_payload in BOOLEAN_PAIRS:
            true_resp = await replay.inject(endpoint, param, true_payload)
            false_resp = await replay.inject(endpoint, param, false_payload)
            if more_access(false_resp, true_resp):
                yield _finding(endpoint, "boolean_based", param, true_payload, "high", "SQL injection boolean bypass signal", {
                    "sub_technique": "boolean_based", "param": param, "true_payload": true_payload,
                    "false_payload": false_payload, "true_status": true_resp.status_code,
                    "false_status": false_resp.status_code,
                })
                return
            if true_resp.status_code != false_resp.status_code and true_resp.status_code < 500 and false_resp.status_code < 500:
                continue

    async def _nosql(self, endpoint, replay, baseline, param):
        if param.get("location") != "json_body":
            return
        for operator in NOSQL:
            payload = json.dumps(operator, separators=(",", ":"))
            resp = await replay.inject(endpoint, param, operator)
            if more_access(baseline, resp):
                yield _finding(endpoint, "nosql_operator", param, payload, "high", "NoSQL operator injection access gain", {
                    "sub_technique": "nosql_operator", "param": param, "payload": payload,
                    "baseline_status": baseline.status_code, "status": resp.status_code,
                })
                return


def _finding(endpoint, sub, param, payload, severity, title, evidence):
    return Finding(
        check_name="sqli", severity=severity, confidence="medium", title=title,
        description=f"Payload reached {param.get('location')} parameter {param.get('path') or param.get('name')} and produced a SQLi signal.",
        evidence=evidence, poc_curl=poc(endpoint, param, str(payload)), remediation="Use parameterized queries and validate input server-side.",
    )
