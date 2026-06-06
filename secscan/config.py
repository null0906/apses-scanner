from __future__ import annotations
import os, tomllib
from dataclasses import dataclass, field
from pathlib import Path

@dataclass(frozen=True)
class TargetConfig:
    name: str
    base_url: str
    notes: str = ""

@dataclass(frozen=True)
class ScanConfig:
    checks: list[str] = field(default_factory=lambda: ["sqli","xss","ssrf","authz","redirect","data","headers","auth","jwt"])
    max_concurrency: int = 2
    rate_limit_rps: int = 2
    max_retries: int = 2
    triage: bool = False

@dataclass(frozen=True)
class AuthConfig:
    script: str = "auth_script.py"
    login_url_pattern: str = "/login"
    session_expiry_minutes: int = 30

@dataclass(frozen=True)
class CrawlerConfig:
    blocklist_extra: list[str] = field(default_factory=list)
    blocklist_override: bool = False

@dataclass(frozen=True)
class LLMConfig:
    max_input_tokens: int = 4000
    truncation_chars: int = 2048
    model: str = "claude-opus-4-5"

@dataclass(frozen=True)
class LogConfig:
    level: str = "INFO"
    format: str = "console"

@dataclass(frozen=True)
class Config:
    target: TargetConfig
    scan: ScanConfig
    auth: AuthConfig
    crawler: CrawlerConfig
    llm: LLMConfig
    log: LogConfig
    database_url: str = ""
    anthropic_api_key: str = ""
    interactsh_url: str = "http://localhost:9000"

def load_config(target_name: str, targets_dir: Path | None = None) -> Config:
    targets_dir = targets_dir or Path("targets")
    raw = {}
    path = targets_dir / target_name / "secscan.toml"
    if path.exists():
        with open(path, "rb") as fh:
            raw = tomllib.load(fh)
    t, s, a, c, l, lg = (raw.get(k, {}) for k in ("target", "scan", "auth", "crawler", "llm", "logging"))
    return Config(
        target=TargetConfig(t.get("name", target_name), t.get("base_url", ""), t.get("notes", "")),
        scan=ScanConfig(s.get("checks", ScanConfig().checks), s.get("max_concurrency", 2), s.get("rate_limit_rps", 2), s.get("max_retries", 2), s.get("triage", False)),
        auth=AuthConfig(a.get("script", "auth_script.py"), a.get("login_url_pattern", "/login"), a.get("session_expiry_minutes", 30)),
        crawler=CrawlerConfig(c.get("blocklist_extra", []), c.get("blocklist_override", False)),
        llm=LLMConfig(l.get("max_input_tokens", 4000), l.get("truncation_chars", 2048), l.get("model", "claude-opus-4-5")),
        log=LogConfig(lg.get("level", "INFO"), lg.get("format", "console")),
        database_url=os.environ.get("DATABASE_URL", ""),
        anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
        interactsh_url=os.environ.get("INTERACTSH_URL", "http://localhost:9000"),
    )
