from __future__ import annotations

from pathlib import Path
from typing import Any, Awaitable, Callable

from .auth import Session, bootstrap_session


class DeadSessionError(RuntimeError):
    pass


class SessionKeeper:
    def __init__(self, config: Any, target_dir: Path | None = None, bootstrap: Callable[..., Awaitable[Session]] = bootstrap_session):
        self.config = config
        self.target_dir = target_dir
        self.bootstrap = bootstrap
        self._session: Session | None = None

    async def get_session(self) -> Session:
        if self._session is None or self._session.is_expired():
            self._session = await self.bootstrap(self.config, self.target_dir)
        return self._session

    async def refresh(self) -> Session:
        self._session = await self.bootstrap(self.config, self.target_dir)
        return self._session
