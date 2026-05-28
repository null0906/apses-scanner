from __future__ import annotations
import html
from pathlib import Path
from .models import ScanReport
from secscan.triage.playbook import guidance

CSS = """
body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;margin:0;color:#18202a;background:#f7f8fa}header{background:#111827;color:white;padding:24px 32px}main{padding:24px 32px}.summary{display:flex;gap:16px;flex-wrap:wrap}.metric{background:white;border:1px solid #d7dce3;border-radius:6px;padding:14px 16px;min-width:140px}table{width:100%;border-collapse:collapse;background:white;margin-top:18px}th,td{border-bottom:1px solid #d7dce3;text-align:left;padding:10px;vertical-align:top}th{background:#edf0f4}.sev-critical{color:#991b1b;font-weight:700}.sev-high{color:#b45309;font-weight:700}.sev-medium{color:#0369a1;font-weight:700}.sev-low{color:#4b5563}pre{white-space:pre-wrap;background:#f1f5f9;padding:10px;border-radius:6px;max-width:900px;overflow:auto}
"""

def write_html_report(report: ScanReport, path: str | Path) -> Path:
    path = Path(path)
    rows = []
    for result in report.check_results:
        if not result.findings:
            rows.append(f"<tr><td>{esc(result.check_name)}</td><td>{esc(result.endpoint)}</td><td colspan='5'>No findings</td></tr>")
            continue
        for finding in result.findings:
            rows.append("<tr>" + "".join([
                f"<td>{esc(finding.check_name)}</td>", f"<td>{esc(result.endpoint)}</td>",
                f"<td class='sev-{esc(finding.severity.lower())}'>{esc(finding.severity)}</td>",
                f"<td>{esc(finding.title)}</td>", f"<td>{esc(finding.description)}</td>",
                f"<td>{esc(finding.remediation or guidance(finding.check_name))}</td>",
                f"<td><pre>{esc(str(finding.evidence))}</pre></td>",
            ]) + "</tr>")
    counts = "".join(f"<div class='metric'><b>{esc(k.title())}</b><br>{v}</div>" for k, v in report.severity_counts.items())
    html_doc = f"<!doctype html><html><head><meta charset='utf-8'><title>SecScan Report</title><style>{CSS}</style></head><body><header><h1>SecScan Report</h1><p>{esc(report.target)} · {esc(report.timestamp.isoformat())}</p></header><main><section class='summary'><div class='metric'><b>Risk Score</b><br>{report.risk_score}/100</div>{counts}</section><table><thead><tr><th>Check</th><th>Endpoint</th><th>Severity</th><th>Finding</th><th>Description</th><th>Remediation</th><th>Evidence</th></tr></thead><tbody>{''.join(rows)}</tbody></table></main></body></html>"
    path.write_text(html_doc, encoding="utf-8")
    return path


def esc(value) -> str:
    return html.escape(str(value), quote=True)
