from __future__ import annotations

import logging
from dataclasses import dataclass, field

_LOG = logging.getLogger(__name__)

DEFAULT_ACTION_PATTERNS = [
    "delete", "remove", "destroy", "deactivate", "disable", "cancel", "revoke",
    "terminate", "purge", "wipe", "reset", "logout", "signout", "sign-out", "log-out",
]
DEFAULT_BUTTON_PATTERNS = [
    "delete", "remove", "destroy", "deactivate", "disable", "cancel", "revoke",
    "terminate", "purge", "wipe", "reset", "log out", "sign out",
]


@dataclass(frozen=True)
class BlocklistChecker:
    extra_patterns: list[str] = field(default_factory=list)
    override_defaults: bool = False

    def __post_init__(self):
        if self.override_defaults:
            _LOG.warning("Default crawler destructive-action blocklist disabled by config override.")

    @property
    def action_patterns(self) -> list[str]:
        defaults = [] if self.override_defaults else DEFAULT_ACTION_PATTERNS
        return [p.lower() for p in defaults + list(self.extra_patterns or [])]

    @property
    def button_patterns(self) -> list[str]:
        defaults = [] if self.override_defaults else DEFAULT_BUTTON_PATTERNS
        return [p.lower() for p in defaults + list(self.extra_patterns or [])]

    def blocks_form(self, form) -> bool:
        action = str(getattr(form, "action", "") or "").lower()
        if any(pattern in action for pattern in self.action_patterns):
            return True
        if self.blocks_button_text(getattr(form, "submit_text", "")):
            return True
        for field in getattr(form, "fields", []) or []:
            if str(getattr(field, "name", "")).lower() == "_method" and str(getattr(field, "value", "")).upper() in {"DELETE", "PUT"}:
                return True
        return False

    def blocks_button_text(self, text: str) -> bool:
        lowered = str(text or "").lower()
        return any(pattern in lowered for pattern in self.button_patterns)
