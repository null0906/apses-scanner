from __future__ import annotations
import json
from pathlib import Path
from .models import ScanReport


def write_json_report(report: ScanReport, path: str | Path) -> Path:
    path = Path(path)
    path.write_text(json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True), encoding="utf-8")
    return path
