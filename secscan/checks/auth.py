from __future__ import annotations
from typing import AsyncIterator
from .base import Check, Endpoint, Finding


class AuthCheck(Check):
    name = "auth"
    description = "Authentication behavior checks."

    async def run(self, endpoint: Endpoint, session, replay) -> AsyncIterator[Finding]:
        if False:
            yield Finding("auth", "low", "low", "placeholder", "", {}, "", "")
        return
