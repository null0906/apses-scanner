from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from secscan.checks import REGISTERED_CHECKS, get_checks
from secscan.checks.auth import AuthCheck
from secscan.checks.authz import AuthzCheck, _resource_identifier_param
from secscan.checks.base import Endpoint
from secscan.checks.data import DataExposureCheck, _high_entropy
from secscan.checks.headers import HeadersCheck
from secscan.checks.jwt import JWTCheck, _mutations, _token_sources
from secscan.checks.redirect import RedirectCheck
from secscan.checks.sqli import SQLiCheck
from secscan.checks.ssrf import SSRFCheck, _metadata_evidence
from secscan.checks.xss import XSSCheck
from secscan.config import load_config
from secscan.crawler.engine import CrawlerEngine, _host, _request_to_entry
from secscan.ingest.har_parser import HarEntry
from secscan.ingest.normalizer import normalize_entries
from secscan.replay.engine import PayloadInjector, ReplayRequest, ReplayResponse
from secscan.report.html_report import write_html_report
from secscan.report.json_report import write_json_report
from secscan.report.models import ScanReport
from secscan.runner import RunnerConfig, run_scan, risk_score, severity_counts
from secscan.session.auth import Session, _find_token_field, _select_bearer_token
from secscan.session.keeper import SessionKeeper
from secscan.triage.llm import prompt_for
from secscan.triage.playbook import guidance
from secscan.utils.http import sanitize_for_postgres


class FakeReplay:
    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.injector = PayloadInjector()
        self.requests = []

    async def baseline(self, endpoint):
        return ReplayResponse(200, {"content-type": "application/json"}, b'{"ok":true}', url=endpoint.sample_url)

    async def inject(self, endpoint, param, payload):
        self.requests.append((param, payload))
        if self.responses:
            item = self.responses.pop(0)
            return item(payload) if callable(item) else item
        return ReplayResponse(200, {"content-type": "application/json"}, str(payload).encode(), url=endpoint.sample_url)

    async def replay(self, request):
        self.requests.append(request)
        return ReplayResponse(401, {"content-type": "application/json"}, b'{"error":"bad token"}', url=request.url)


def ep(params=None, body=None, headers=None, url="http://example.test/api?q="):
    return Endpoint("POST" if body else "GET", url, url, body, headers or {}, params or [], id=1)


@pytest.mark.asyncio
async def test_registered_checks_import_and_instantiate():
    assert sorted(REGISTERED_CHECKS) == ["auth", "authz", "data", "headers", "jwt", "redirect", "sqli", "ssrf", "xss"]
    assert [c.name for c in get_checks(["sqli", "headers"])] == ["sqli", "headers"]


@pytest.mark.asyncio
async def test_sqli_error_based_flags_5xx_and_signature():
    endpoint = ep([{"name": "email", "path": "email", "location": "json_body", "classification": "mutable", "sample_value": "a@b.c"}], {"raw": '{"email":"a@b.c"}', "json": {"email": "a@b.c"}})
    replay = FakeReplay([ReplayResponse(500, {}, b"SequelizeDatabaseError: sqlite/query.js")])
    findings = [f async for f in SQLiCheck().run(endpoint, Session(), replay)]
    assert findings and findings[0].evidence["status_broke_query"] is True


@pytest.mark.asyncio
async def test_headers_data_xss_redirect_ssrf_authz_checks():
    endpoint = ep([{"name": "q", "path": "q", "location": "query", "classification": "mutable", "sample_value": ""}])
    headers = [f async for f in HeadersCheck().run(endpoint, Session(), FakeReplay())]
    assert {f.check_name for f in headers} == {"headers"}

    data_replay = FakeReplay()
    async def data_baseline(_):
        return ReplayResponse(200, {}, b'{"token":"eyJabc.def.ghi","email":"a@example.com","stack":"dialects/sqlite"}')
    data_replay.baseline = data_baseline
    data = [f async for f in DataExposureCheck().run(endpoint, Session(), data_replay)]
    assert {f.check_name for f in data} == {"data"}

    xss_replay = FakeReplay([ReplayResponse(200, {"content-type": "text/html"}, b'<script>alert(1)</script>')])
    xss = [f async for f in XSSCheck().run(endpoint, Session(), xss_replay)]
    assert xss[0].check_name == "xss"

    redirect_replay = FakeReplay([ReplayResponse(302, {"location": "https://evil.example"}, b"")])
    redir_endpoint = ep([{"name": "next", "path": "next", "location": "query", "classification": "mutable", "sample_value": ""}])
    redirs = [f async for f in RedirectCheck().run(redir_endpoint, Session(), redirect_replay)]
    assert redirs[0].check_name == "redirect"

    assert not _metadata_evidence('{"items":[],"is-active":true}')
    assert _metadata_evidence("instance-id\ni-1234abcd")
    ssrf = [f async for f in SSRFCheck().run(endpoint, Session(), FakeReplay())]
    assert ssrf == []

    assert not _resource_identifier_param({"name": "email", "sample_value": "abc123"})
    login_ep = ep([
        {"name": "email", "sample_value": "abc123", "classification": "mutable"},
        {"name": "password", "sample_value": "deadbeef", "classification": "mutable"},
    ], {"raw": '{"email":"abc123","password":"deadbeef"}'})
    assert [f async for f in AuthzCheck().run(login_ep, Session(), FakeReplay())] == []
    path_ep = Endpoint("GET", "http://example.test/api/recycles/a1b2c3", "http://example.test/api/recycles/a1b2c3", None, {}, [])
    assert [f async for f in AuthzCheck().run(path_ep, Session(), FakeReplay())] == []
    templated_path_ep = Endpoint("GET", "http://example.test/api/recycles/{hash}", "http://example.test/api/recycles/a1b2c3", None, {}, [])
    path_authz = [f async for f in AuthzCheck().run(templated_path_ep, Session(), FakeReplay())]
    assert path_authz[0].evidence["segment"] == "a1b2c3"
    authz_ep = ep([{"name": "object_id", "sample_value": "abc123", "classification": "mutable"}])
    authz = [f async for f in AuthzCheck().run(authz_ep, Session(), FakeReplay())]
    assert authz[0].evidence["sub_technique"] == "hash_id_weakness"
    assert [f async for f in AuthCheck().run(endpoint, Session(), FakeReplay())] == []


def test_payload_injector_json_form_query_and_headers_are_safe():
    endpoint = ep(
        [{"name": "email", "path": "email", "location": "json_body", "classification": "mutable"}],
        {"raw": '{"email":"a","nested":{"x":"y"}}', "json": {"email": "a"}},
        {"Content-Length": "3", "If-None-Match": "abc", "Content-Type": "application/json"},
    )
    inj = PayloadInjector()
    req = inj.build(endpoint, {"location": "json_body", "name": "email", "path": "email"}, "' OR 1=1--")
    assert "content-length" not in {k.lower() for k in req.headers}
    assert "if-none-match" not in {k.lower() for k in req.headers}
    assert json.loads(req.body)["email"] == "' OR 1=1--"

    form = ep(body={"raw": "q=old", "form": {"q": "old"}}, headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert "q=new" in inj.build(form, {"location": "form", "name": "q"}, "new").body
    assert "q=new" in inj.build(ep(), {"location": "query", "name": "q"}, "new").url
    assert inj.build(ep(), {"location": "header", "name": "Authorization"}, "Bearer x").headers["Authorization"] == "Bearer x"
    assert ReplayRequest("GET", "http://x", {"If-Modified-Since": "y"}).sanitized_headers() == {}


def test_normalizer_json_and_empty_and_auth_classification():
    entries = [
        HarEntry("POST", "http://example.test/rest/user/login", {"Content-Type": "application/json"}, {}, "application/json", '{"email":"admin@x","password":"admin123","profile":{"name":"a"}}'),
        HarEntry("GET", "http://example.test/rest/products/search?q=", {}, {"q": ""}),
        HarEntry("GET", "http://example.test/api?token=eyJabc.def.ghi", {}, {"token": "eyJabc.def.ghi"}),
    ]
    endpoints = normalize_entries(entries)
    params = [p for e in endpoints for p in e.mutable_params]
    by_path = {p["path"]: p for p in params}
    assert by_path["email"]["location"] == "json_body"
    assert by_path["email"]["classification"] == "mutable"
    assert by_path["profile.name"]["classification"] == "mutable"
    assert by_path["q"]["classification"] == "mutable"
    assert by_path["token"]["classification"] == "auth_bound"


def test_session_helpers_config_reports_and_utils(tmp_path):
    token = "eyJabc.def.ghi"
    assert _find_token_field('{"token":"eyJabc.def.ghi"}') == token
    assert _select_bearer_token([f"Bearer {token}"], [], [], {}) == token
    session = Session(cookies=[{"name": "sid", "value": "1"}], headers={"Authorization": "Bearer x"}, expires_at=datetime.now(timezone.utc) + timedelta(minutes=1))
    assert not session.is_expired()
    assert session.to_httpx_kwargs()["cookies"] == {"sid": "1"}
    assert sanitize_for_postgres("a\x00b") == "ab"
    assert _high_entropy("https://cdn.example.com/static/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.js") is None
    assert _high_entropy("/static/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.js") is None
    assert _high_entropy("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.sig") is None
    assert _high_entropy("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") is not None
    config = load_config("missing-target", targets_dir=tmp_path)
    assert config.scan.rate_limit_rps == 2 and config.scan.max_concurrency == 2
    assert guidance("sqli") and prompt_for("sqli")

    class Result:
        target = "t"
        timestamp = datetime.now(timezone.utc)
        severity_counts = {"critical": 0, "high": 1, "medium": 1, "low": 1, "info": 0}
        risk_score = 14
        check_results = []
    report = ScanReport.from_scan_result(Result())
    assert write_json_report(report, tmp_path / "r.json").exists()
    assert write_html_report(report, tmp_path / "r.html").exists()


@pytest.mark.asyncio
async def test_runner_and_keeper(monkeypatch):
    async def fake_bootstrap(config, target_dir=None):
        return Session(headers={"Authorization": "Bearer x"})
    keeper = SessionKeeper(object(), bootstrap=fake_bootstrap)
    assert (await keeper.get_session()).headers["Authorization"] == "Bearer x"
    assert (await keeper.refresh()).headers["Authorization"] == "Bearer x"

    endpoint = ep()
    result = await run_scan("http://example.test", [endpoint], Session(), ["auth"], RunnerConfig(max_concurrency=1, rate_limit_rps=100, max_retries=0))
    assert result.target == "http://example.test"
    assert result.severity_counts["high"] == 0
    assert risk_score({"critical": 0, "high": 1, "medium": 13, "low": 26}) in range(35, 51)
    assert risk_score({"critical": 0, "high": 3, "medium": 16, "low": 26}) in range(60, 70)
    assert severity_counts([])["critical"] == 0


def test_jwt_helpers_and_no_access_gain():
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"
    session = Session(headers={"Authorization": f"Bearer {token}"})
    assert _token_sources(session) == [token]
    assert len(_mutations(token)) == 2


@pytest.mark.asyncio
async def test_crawler_engine_captures_same_domain_xhr_and_drops_external(monkeypatch):
    class Target:
        base_url = "http://app.example.test"

    class Scan:
        max_concurrency = 1
        rate_limit_rps = 100

    class Config:
        target = Target()
        scan = Scan()

    class FakeRequest:
        def __init__(self, url, resource_type="xhr"):
            self.url = url
            self.resource_type = resource_type
            self.method = "GET"
            self.headers = {"content-type": "application/json"}
            self.post_data = None

    class FakeRoute:
        def __init__(self, url):
            self.request = FakeRequest(url, "document")
            self.continued = False

        async def continue_(self):
            self.continued = True

    class FakePage:
        def __init__(self):
            self.handlers = {}
            self.route_handler = None

        async def route(self, pattern, handler):
            self.route_handler = handler

        def on(self, event, handler):
            self.handlers[event] = handler

        async def goto(self, url, wait_until=None):
            route = FakeRoute(url)
            await self.route_handler(route)
            assert route.continued is True
            await self.handlers["request"](FakeRequest("http://app.example.test/api/me?x=1", "xhr"))
            await self.handlers["request"](FakeRequest("http://cdn.example.test/asset.js", "xhr"))
            await self.handlers["request"](FakeRequest("http://app.example.test/app.js", "script"))

    class FakeContext:
        def __init__(self):
            self.cookies = None

        async def add_cookies(self, cookies):
            self.cookies = cookies

        async def new_page(self):
            return FakePage()

    class FakeBrowser:
        async def new_context(self, **kwargs):
            self.context_kwargs = kwargs
            return FakeContext()

        async def close(self):
            self.closed = True

    class FakeChromium:
        async def launch(self, headless=True):
            return FakeBrowser()

    class FakePlaywright:
        def __init__(self):
            self.chromium = FakeChromium()

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr("secscan.crawler.engine.async_playwright", lambda: FakePlaywright())
    records = await CrawlerEngine(Config(), Session(cookies=[{"name": "sid", "value": "1"}], headers={"Authorization": "Bearer x"})).crawl("app")
    assert len(records) == 1
    assert records[0].url == "http://app.example.test/api/me?x=1"
    assert records[0].query_params == {"x": "1"}
    assert _host("http://app.example.test/a") == "app.example.test"


def test_crawler_request_to_entry_preserves_post_body_and_content_type():
    class Request:
        method = "POST"
        url = "http://app.example.test/api"
        headers = {"content-type": "application/json"}
        post_data = '{"name":"secscan"}'

    entry = _request_to_entry(Request())
    assert entry.method == "POST"
    assert entry.post_data_mime == "application/json"
    assert entry.post_data_text == '{"name":"secscan"}'


def test_parse_har_and_request_helpers(tmp_path):
    har = {"log": {"entries": [{"request": {"method": "POST", "url": "http://x.test/a?x=1", "headers": [{"name": "H", "value": "v"}], "queryString": [{"name": "x", "value": "1"}], "postData": {"mimeType": "application/x-www-form-urlencoded", "text": "a=b"}}, "response": {"status": 200, "headers": [{"name": "content-type", "value": "text/plain"}], "content": {"text": "ok"}}}]}}
    path = tmp_path / "s.har"
    path.write_text(json.dumps(har), encoding="utf-8")
    from secscan.ingest.har_parser import parse_har
    entries = parse_har(path)
    assert entries[0].method == "POST" and entries[0].query_params == {"x": "1"}
    endpoints = normalize_entries(entries)
    assert endpoints[0].request_body["form"] == {"a": "b"}


@pytest.mark.asyncio
async def test_replay_engine_retry_and_rate_limiter(monkeypatch):
    from secscan.replay.engine import ReplayEngine
    from secscan.replay.ratelimit import RateLimiter

    limiter = RateLimiter(max_concurrency=1, rate_limit_rps=100)
    async with await limiter.acquire("http://example.test/a"):
        pass

    engine = ReplayEngine(Session(), rate_limiter=limiter, max_retries=1)
    calls = []
    async def fake_send_once(request):
        calls.append(request)
        if len(calls) == 1:
            return ReplayResponse(429, {"Retry-After": "0"}, b"")
        return ReplayResponse(200, {}, b"ok")
    engine._send_once = fake_send_once
    resp = await engine.replay(ReplayRequest("GET", "http://example.test/a", {"If-Range": "x"}))
    assert resp.status_code == 200
    assert calls[0].headers == {}
    assert engine._retry_delay(ReplayResponse(503, {"Retry-After": "0"}, b""), 0) == 0


@pytest.mark.asyncio
async def test_jwt_run_access_gain_and_rejection():
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"
    session = Session(headers={"Authorization": f"Bearer {token}"})
    endpoint = ep(url="http://example.test/api/me")

    class JWTReplay(FakeReplay):
        async def baseline(self, endpoint):
            return ReplayResponse(401, {}, b'{"error":"unauthorized"}', url=endpoint.sample_url)
        async def replay(self, request):
            return ReplayResponse(200, {}, b'{"token":"new","role":"admin"}', url=request.url)

    findings = [f async for f in JWTCheck().run(endpoint, session, JWTReplay())]
    assert findings and findings[0].check_name == "jwt"

    class RejectReplay(JWTReplay):
        async def replay(self, request):
            return ReplayResponse(401, {}, b'{"error":"bad"}', url=request.url)

    assert [f async for f in JWTCheck().run(endpoint, session, RejectReplay())] == []


@pytest.mark.asyncio
async def test_sqli_boolean_nosql_and_non_mutable_paths():
    endpoint = ep([{"name": "email", "path": "email", "location": "json_body", "classification": "mutable", "sample_value": "a"}], {"raw": '{"email":"a"}', "json": {"email": "a"}})

    class BoolReplay(FakeReplay):
        async def baseline(self, endpoint):
            return ReplayResponse(401, {}, b'{"error":"bad"}')
        async def inject(self, endpoint, param, payload):
            if isinstance(payload, str) and "1=1" in payload:
                return ReplayResponse(200, {}, b'{"token":"ok"}')
            return ReplayResponse(401, {}, b'{"error":"bad"}')

    findings = [f async for f in SQLiCheck().run(endpoint, Session(), BoolReplay())]
    assert any(f.evidence["sub_technique"] in {"boolean_based", "nosql_operator"} for f in findings)
    empty = ep([{"name": "csrf", "location": "query", "classification": "auth_bound"}])
    assert [f async for f in SQLiCheck().run(empty, Session(), FakeReplay())] == []


def test_report_multiple_findings_and_markdown(tmp_path):
    from secscan.report.models import CheckResult, Finding, ScanReport
    from secscan.reporting.markdown import finding_to_markdown
    finding = Finding(check_name="sqli", severity="high", confidence="high", title="T", description="D", evidence={"a": 1}, remediation="R")
    report = ScanReport(target="t", timestamp=datetime.now(timezone.utc), severity_counts={"high": 1}, risk_score=12, check_results=[CheckResult(check_name="sqli", endpoint="/x", findings=[finding])])
    html_path = write_html_report(report, tmp_path / "multi.html")
    assert "T" in html_path.read_text(encoding="utf-8")
    assert "Severity: high" in finding_to_markdown(finding)


def test_cli_ingest_rejects_har_and_crawl_together():
    from typer.testing import CliRunner
    from secscan.cli.commands import app
    result = CliRunner().invoke(app, ["ingest", "--target", "t", "--har", "tests/fixtures/juice_shop_session.har", "--crawl"])
    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


@pytest.mark.asyncio
async def test_cli_har_ingest_path_uses_existing_normalizer(monkeypatch):
    import secscan.cli.commands as commands
    captured = {}

    async def fake_persist(target_name, base_url, endpoints):
        captured["target_name"] = target_name
        captured["base_url"] = base_url
        captured["count"] = len(endpoints)
        return 3

    monkeypatch.setattr(commands, "_persist_endpoints", fake_persist)
    await commands._ingest("fixture-target", har=Path("tests/fixtures/juice_shop_session.har"), crawl=False)
    assert captured["target_name"] == "fixture-target"
    assert captured["count"] == 12


@pytest.mark.asyncio
async def test_cli_crawl_ingest_normalizes_and_persists(monkeypatch, tmp_path):
    import secscan.cli.commands as commands

    class FakeCrawler:
        def __init__(self, config, session):
            self.config = config
            self.session = session

        async def crawl(self, target_name):
            return [HarEntry("GET", "http://example.test/api/me?x=1", {}, {"x": "1"})]

    async def fake_bootstrap(config, target_dir=None):
        return Session(headers={"Authorization": "Bearer x"})

    captured = {}
    async def fake_persist(target_name, base_url, endpoints):
        captured["target_name"] = target_name
        captured["base_url"] = base_url
        captured["endpoints"] = endpoints
        return len(endpoints)

    target_dir = Path("targets/crawl-unit")
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / "secscan.toml").write_text('[target]\nname="crawl-unit"\nbase_url="http://example.test"\n', encoding="utf-8")
    (target_dir / "auth_script.py").write_text("async def authenticate(page, config):\n    return None\n", encoding="utf-8")

    monkeypatch.setattr(commands, "CrawlerEngine", FakeCrawler)
    monkeypatch.setattr(commands, "bootstrap_session", fake_bootstrap)
    monkeypatch.setattr(commands, "_persist_endpoints", fake_persist)
    await commands._ingest("crawl-unit", crawl=True)
    assert captured["target_name"] == "crawl-unit"
    assert captured["base_url"] == "http://example.test"
    assert len(captured["endpoints"]) == 1
    assert captured["endpoints"][0].mutable_params[0]["path"] == "x"


@pytest.mark.asyncio
async def test_cli_crawl_requires_auth_script(monkeypatch):
    import secscan.cli.commands as commands
    target_dir = Path("targets/no-auth-script")
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / "secscan.toml").write_text('[target]\nname="no-auth-script"\nbase_url="http://example.test"\n', encoding="utf-8")
    auth_script = target_dir / "auth_script.py"
    if auth_script.exists():
        auth_script.unlink()
    with pytest.raises(Exception, match="auth script"):
        await commands._ingest("no-auth-script", crawl=True)


def test_cli_run_crawl_only_flag_skips_checks(monkeypatch):
    from typer.testing import CliRunner
    import secscan.cli.commands as commands
    from secscan.cli.commands import app

    async def fake_run(target, checks, output_dir, rate_limit, max_concurrency, crawl_only=False):
        assert crawl_only is True
        print("Crawl-only mode: 2 endpoints discovered, no checks run.")
        return 0

    monkeypatch.setattr(commands, "_run", fake_run)
    result = CliRunner().invoke(app, ["run", "--target", "t", "--crawl-only"])
    assert result.exit_code == 0
    assert "Crawl-only mode" in result.output
