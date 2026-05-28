from __future__ import annotations
from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field


class Finding(BaseModel):
    check_name: str
    severity: str
    confidence: str
    title: str
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    poc_curl: str = ""
    remediation: str = ""


class CheckResult(BaseModel):
    check_name: str
    endpoint: str
    findings: list[Finding] = Field(default_factory=list)
    error: str | None = None


class ScanReport(BaseModel):
    target: str
    timestamp: datetime
    severity_counts: dict[str, int]
    risk_score: int
    check_results: list[CheckResult] = Field(default_factory=list)

    @classmethod
    def from_scan_result(cls, result) -> "ScanReport":
        return cls(
            target=result.target,
            timestamp=result.timestamp,
            severity_counts=result.severity_counts,
            risk_score=result.risk_score,
            check_results=[CheckResult(
                check_name=r.check_name,
                endpoint=getattr(r.endpoint, "sample_url", getattr(r.endpoint, "url_template", "")),
                error=r.error,
                findings=[Finding(**{k: getattr(f, k) for k in Finding.model_fields}) for f in r.findings],
            ) for r in result.check_results],
        )
