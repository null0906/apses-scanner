from __future__ import annotations
import logging, structlog

def configure_logging(level: str = "INFO", fmt: str = "console") -> None:
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO), format="%(message)s")
    structlog.configure(processors=[structlog.processors.KeyValueRenderer()], cache_logger_on_first_use=True)
