from __future__ import annotations
from .base import Check, Endpoint, Finding
from .sqli import SQLiCheck
from .xss import XSSCheck
from .ssrf import SSRFCheck
from .authz import AuthzCheck
from .redirect import RedirectCheck
from .data import DataExposureCheck
from .headers import HeadersCheck
from .auth import AuthCheck
from .jwt import JWTCheck

REGISTERED_CHECKS = {
    "sqli": SQLiCheck,
    "xss": XSSCheck,
    "ssrf": SSRFCheck,
    "authz": AuthzCheck,
    "redirect": RedirectCheck,
    "data": DataExposureCheck,
    "headers": HeadersCheck,
    "auth": AuthCheck,
    "jwt": JWTCheck,
}

def get_checks(names: list[str] | None = None) -> list[Check]:
    selected = names or list(REGISTERED_CHECKS)
    return [REGISTERED_CHECKS[name]() for name in selected if name in REGISTERED_CHECKS]

__all__ = ["Check", "Endpoint", "Finding", "REGISTERED_CHECKS", "get_checks"]
