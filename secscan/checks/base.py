from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, AsyncIterator

@dataclass
class Endpoint:
    method: str
    url_template: str
    sample_url: str
    request_body: dict | None
    request_headers: dict
    mutable_params: list[dict]
    id: int | None = None

@dataclass
class Finding:
    check_name: str
    severity: str
    confidence: str
    title: str
    description: str
    evidence: dict
    poc_curl: str
    remediation: str
    scan_id: int | None = field(default=None, repr=False)
    endpoint_id: int | None = field(default=None, repr=False)

class Check(ABC):
    name: str
    description: str
    @abstractmethod
    async def run(self, endpoint: Endpoint, session: Any, replay: Any) -> AsyncIterator[Finding]:
        if False:
            yield None
