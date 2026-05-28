from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from secscan.checks import get_checks
from secscan.checks.base import Endpoint, Finding
from secscan.replay.engine import ReplayEngine
from secscan.replay.ratelimit import RateLimiter

SEVERITIES = ["critical", "high", "medium", "low", "info"]


@dataclass
class CheckRunResult:
    check_name: str
    endpoint: Endpoint
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None


@dataclass
class ScanResult:
    target: str
    timestamp: datetime
    check_results: list[CheckRunResult]
    severity_counts: dict[str, int]
    risk_score: int

    @property
    def findings(self) -> list[Finding]:
        return [f for result in self.check_results for f in result.findings]


@dataclass
class RunnerConfig:
    checks: list[str] | None = None
    max_concurrency: int = 2
    rate_limit_rps: int = 2
    timeout: float = 15.0
    max_retries: int = 2


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {sev: 0 for sev in SEVERITIES}
    for finding in findings:
        counts[finding.severity.lower()] = counts.get(finding.severity.lower(), 0) + 1
    return counts


def risk_score(counts: dict[str, int]) -> int:
    weighted = counts.get("critical", 0) * 25 + counts.get("high", 0) * 8 + counts.get("medium", 0) * 2 + counts.get("low", 0) * 0.4
    return max(0, min(100, round(weighted)))


def endpoint_from_url(url: str) -> Endpoint:
    return Endpoint("GET", url, url, None, {}, [])


async def run_scan(target: str, endpoints: list[Endpoint] | None = None, session: Any = None, checks: list[str] | None = None, config: RunnerConfig | None = None, progress: Callable[[CheckRunResult], Awaitable[None] | None] | None = None) -> ScanResult:
    config = config or RunnerConfig(checks=checks)
    check_instances = get_checks(checks or config.checks)
    endpoints = endpoints or [endpoint_from_url(target)]
    limiter = RateLimiter(config.max_concurrency, config.rate_limit_rps)
    sem = asyncio.Semaphore(config.max_concurrency)
    results: list[CheckRunResult] = []

    async with ReplayEngine(session, rate_limiter=limiter, timeout=config.timeout, max_retries=config.max_retries) as replay:
        async def run_one(check, endpoint):
            async with sem:
                result = CheckRunResult(check.name, endpoint)
                try:
                    result.findings = [finding async for finding in check.run(endpoint, session, replay)]
                except Exception as exc:
                    result.error = f"{type(exc).__name__}: {exc}"
                results.append(result)
                if progress:
                    maybe = progress(result)
                    if asyncio.iscoroutine(maybe):
                        await maybe
                return result

        await asyncio.gather(*(run_one(check, endpoint) for endpoint in endpoints for check in check_instances))

    findings = [finding for result in results for finding in result.findings]
    counts = severity_counts(findings)
    return ScanResult(target=target, timestamp=datetime.now(timezone.utc), check_results=results, severity_counts=counts, risk_score=risk_score(counts))
