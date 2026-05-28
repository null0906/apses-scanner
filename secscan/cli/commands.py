from __future__ import annotations

import asyncio
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import typer
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from secscan.checks.base import Endpoint as CheckEndpoint
from secscan.config import load_config
from secscan.ingest.har_parser import parse_har
from secscan.ingest.normalizer import normalize_entries
from secscan.models.schema import Base, Endpoint, Finding, Scan, Session as DbSession, Target
from secscan.report.html_report import write_html_report
from secscan.report.json_report import write_json_report
from secscan.report.models import CheckResult, Finding as ReportFinding, ScanReport
from secscan.runner import RunnerConfig, run_scan
from secscan.session.auth import Session, bootstrap_session
from secscan.utils.http import sanitize_for_postgres

app = typer.Typer(help="SecScan v0.1 authenticated captured-surface scanner")


def _database_url() -> str:
    import os
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise typer.BadParameter("DATABASE_URL is not set")
    return url


def _engine():
    return create_async_engine(_database_url(), future=True)


@app.command()
def init(target: str = typer.Option(..., "--target"), base_url: str = typer.Option(..., "--base-url")):
    """Create local target config/auth template and DB target row."""
    target_dir = Path("targets") / target
    target_dir.mkdir(parents=True, exist_ok=True)
    template = Path("templates/secscan.toml.template")
    auth_template = Path("templates/auth_script.py.template")
    config_path = target_dir / "secscan.toml"
    if template.exists() and not config_path.exists():
        text = template.read_text(encoding="utf-8").replace("{{ target_name }}", target).replace("{{ base_url }}", base_url)
        config_path.write_text(text, encoding="utf-8")
    if auth_template.exists() and not (target_dir / "auth_script.py").exists():
        shutil.copyfile(auth_template, target_dir / "auth_script.py")
    asyncio.run(_ensure_target(target, base_url))
    typer.echo(f"Initialized target {target} at {target_dir}")


@app.command()
def ingest(har: Path = typer.Option(..., "--har"), target: str = typer.Option(..., "--target")):
    """Parse a HAR and store normalized endpoints for a target."""
    asyncio.run(_ingest(har, target))


@app.command()
def run(
    target: str = typer.Option(..., "--target"),
    checks: str | None = typer.Option(None, "--checks"),
    output_dir: Path = typer.Option(Path("."), "--output-dir"),
    rate_limit: float | None = typer.Option(None, "--rate-limit"),
    max_concurrency: int | None = typer.Option(None, "--max-concurrency"),
):
    """Run selected checks against stored endpoints."""
    code = asyncio.run(_run(target, checks, output_dir, rate_limit, max_concurrency))
    raise typer.Exit(code=code)


@app.command()
def report(target: str = typer.Option(..., "--target"), format: str = typer.Option("html", "--format"), output: Path | None = typer.Option(None, "--output")):
    """Generate a report from stored findings."""
    asyncio.run(_report(target, format, output))


async def _ensure_target(name: str, base_url: str) -> None:
    engine = _engine(); SessionLocal = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with SessionLocal() as db:
        existing = (await db.execute(select(Target).where(Target.name == name))).scalar_one_or_none()
        if existing:
            existing.base_url = base_url or existing.base_url
        else:
            db.add(Target(name=name, base_url=base_url, notes=""))
        await db.commit()
    await engine.dispose()


async def _ingest(har: Path, target_name: str) -> None:
    config = load_config(target_name)
    entries = parse_har(har)
    endpoints = normalize_entries(entries, config.target.base_url)
    engine = _engine(); SessionLocal = async_sessionmaker(engine, expire_on_commit=False)
    async with SessionLocal() as db:
        target = (await db.execute(select(Target).where(Target.name == target_name))).scalar_one_or_none()
        if target is None:
            target = Target(name=target_name, base_url=config.target.base_url, notes="")
            db.add(target); await db.flush()
        count = 0
        for ep in endpoints:
            existing = (await db.execute(select(Endpoint).where(Endpoint.target_id == target.id, Endpoint.method == ep.method, Endpoint.url_template == ep.url_template))).scalar_one_or_none()
            values = dict(target_id=target.id, method=ep.method, url_template=ep.url_template, sample_url=ep.sample_url, request_headers=ep.request_headers or {}, request_body=ep.request_body, mutable_params=ep.mutable_params or [])
            if existing:
                for key, value in values.items():
                    setattr(existing, key, value)
            else:
                db.add(Endpoint(**values)); count += 1
        await db.commit()
    await engine.dispose()
    typer.echo(f"Ingested {len(endpoints)} endpoints ({count} new) for {target_name}")


async def _run(target_name: str, checks_csv: str | None, output_dir: Path, rate_limit: float | None, max_concurrency: int | None) -> int:
    config = load_config(target_name)
    selected = [c.strip() for c in checks_csv.split(",") if c.strip()] if checks_csv else list(config.scan.checks)
    engine = _engine(); SessionLocal = async_sessionmaker(engine, expire_on_commit=False)
    async with SessionLocal() as db:
        target = (await db.execute(select(Target).where(Target.name == target_name))).scalar_one_or_none()
        if target is None:
            raise typer.BadParameter(f"Unknown target {target_name}; run secscan init first")
        rows = (await db.execute(select(Endpoint).where(Endpoint.target_id == target.id))).scalars().all()
        endpoints = [_to_check_endpoint(row) for row in rows]
        if not endpoints:
            raise typer.BadParameter(f"No endpoints for {target_name}; run secscan ingest first")
        scan = Scan(target_id=target.id, status="running", summary={}, checks_enabled=selected, triage_enabled=False, config={})
        db.add(scan); await db.flush()
        try:
            session = await bootstrap_session(config, Path("targets") / target_name)
        except Exception as exc:
            typer.echo(f"Session bootstrap failed, continuing without authenticated browser session: {exc}", err=True)
            session = Session()
        db.add(DbSession(target_id=target.id, user_label="default", cookies=session.cookies, headers=session.headers, storage=session.storage_state, valid_until=session.expires_at))
        await db.flush()

        row_by_id = {row.id: row for row in rows}
        row_by_url = {row.sample_url: row for row in rows}

        async def progress(result):
            ep = getattr(result.endpoint, "sample_url", getattr(result.endpoint, "url_template", ""))
            typer.echo(f"[{result.check_name}] {ep} findings={len(result.findings)}" + (f" error={result.error}" if result.error else ""))

        result = await run_scan(target.base_url, endpoints, session, selected, RunnerConfig(
            checks=selected,
            max_concurrency=max_concurrency or config.scan.max_concurrency,
            rate_limit_rps=rate_limit or config.scan.rate_limit_rps,
            max_retries=config.scan.max_retries,
        ), progress)
        for check_result in result.check_results:
            db_ep = row_by_id.get(getattr(check_result.endpoint, "id", None)) or row_by_url.get(check_result.endpoint.sample_url)
            if db_ep is None:
                db_ep = rows[0]
            for finding in check_result.findings:
                await _insert_finding(db, scan.id, db_ep.id, finding)
        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.summary = {"severity_counts": result.severity_counts, "risk_score": result.risk_score, "checks": selected}
        await db.commit()
        high_or_critical = result.severity_counts.get("critical", 0) + result.severity_counts.get("high", 0)
    await engine.dispose()
    typer.echo(f"Scan complete: risk={result.risk_score} findings={len(result.findings)}")
    return 1 if high_or_critical else 0


async def _report(target_name: str, format: str, output: Path | None) -> None:
    engine = _engine(); SessionLocal = async_sessionmaker(engine, expire_on_commit=False)
    async with SessionLocal() as db:
        target = (await db.execute(select(Target).where(Target.name == target_name))).scalar_one_or_none()
        if target is None:
            raise typer.BadParameter(f"Unknown target {target_name}")
        scan = (await db.execute(select(Scan).where(Scan.target_id == target.id).order_by(Scan.id.desc()))).scalars().first()
        if scan is None:
            raise typer.BadParameter(f"No scans for {target_name}")
        rows = (await db.execute(select(Finding, Endpoint).join(Endpoint, Finding.endpoint_id == Endpoint.id).where(Finding.scan_id == scan.id))).all()
        grouped: dict[str, CheckResult] = {}
        for finding, endpoint in rows:
            cr = grouped.setdefault(finding.check_name, CheckResult(check_name=finding.check_name, endpoint=endpoint.sample_url, findings=[]))
            cr.findings.append(ReportFinding(check_name=finding.check_name, severity=finding.severity, confidence=finding.confidence, title=finding.title, description=finding.description, evidence=finding.evidence or {}, poc_curl=finding.poc_curl, remediation=finding.remediation))
        report_model = ScanReport(target=target.name, timestamp=scan.completed_at or scan.started_at, severity_counts=(scan.summary or {}).get("severity_counts", {}), risk_score=(scan.summary or {}).get("risk_score", 0), check_results=list(grouped.values()))
    await engine.dispose()
    output = output or Path(f"{target_name}-secscan-report.{format}")
    if format == "json":
        write_json_report(report_model, output)
    else:
        write_html_report(report_model, output)
    typer.echo(f"Wrote {output}")


def _to_check_endpoint(row: Endpoint) -> CheckEndpoint:
    return CheckEndpoint(method=row.method, url_template=row.url_template, sample_url=row.sample_url, request_body=row.request_body, request_headers=row.request_headers or {}, mutable_params=row.mutable_params or [], id=row.id)


def _sanitize_value(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize_for_postgres(value)
    if isinstance(value, dict):
        return {sanitize_for_postgres(str(k)): _sanitize_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_value(v) for v in value]
    return value


async def _insert_finding(db, scan_id: int, endpoint_id: int, finding) -> None:
    evidence = _sanitize_value(finding.evidence or {})
    sub = sanitize_for_postgres(str(evidence.get("sub_technique") or evidence.get("technique") or "default"))
    existing = (await db.execute(select(Finding).where(
        Finding.scan_id == scan_id,
        Finding.endpoint_id == endpoint_id,
        Finding.check_name == sanitize_for_postgres(finding.check_name),
        Finding.evidence["sub_technique"].astext == sub,
    ))).scalar_one_or_none()
    if existing is not None:
        return
    db.add(Finding(
        scan_id=scan_id,
        endpoint_id=endpoint_id,
        check_name=sanitize_for_postgres(finding.check_name),
        severity=sanitize_for_postgres(finding.severity),
        confidence=sanitize_for_postgres(finding.confidence),
        title=sanitize_for_postgres(finding.title)[:500],
        description=sanitize_for_postgres(finding.description),
        evidence=evidence,
        poc_curl=sanitize_for_postgres(finding.poc_curl),
        remediation=sanitize_for_postgres(finding.remediation),
    ))
