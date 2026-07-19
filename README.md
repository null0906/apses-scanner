# SecScan v0.2

## 1. What SecScan Is

SecScan is an internal authenticated DAST tool for SecComply VAPT work. It takes a captured browsing session, normalizes the endpoints from a HAR file, bootstraps authentication with a Playwright `auth_script.py`, replays the captured API surface, and runs vulnerability checks against it. It is a force-multiplier for manual VAPT, not a replacement for manual testing. A clean SecScan report means "SecScan did not find issues in the captured surface"; it does not mean the application is secure. As of v0.2, SecScan also includes an authenticated crawler that can discover pages and exercise inputs automatically, replacing the manual HAR capture step for supported targets.

## 2. What It Reliably Finds

SecScan is strongest on captured or crawled API endpoints and deterministic response analysis.

- SQL injection on captured, injectable parameters in query strings, form fields, and JSON body fields. Boolean-based and error-based SQLi are confirmed working on OWASP Juice Shop.
- Missing or misconfigured security headers, including CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and unsafe CORS/header patterns.
- Sensitive data exposure in responses, including JWTs, high-entropy secrets, verbose error leakage, and PII-style patterns.
- Broader API surface on targets with accessible routes: v0.2's crawler discovers endpoints automatically by navigating the rendered application, following same-domain links, submitting safe form values, and running a forced-browsing wordlist pass. Validated on Juice Shop (25 endpoints vs 14 from manual HAR), DVWA (reflected XSS confirmed), and a production CRM (29 authenticated API endpoints discovered).

Latest Juice Shop tuning showed real findings from `sqli`, `headers`, and `data`.

## 3. What It Does Not Find Yet

Read this before using SecScan on a client target. These are not edge cases; they are current boundaries.

- XSS: the XSS check detects server-side reflected XSS where the payload appears in an HTML response body (confirmed working on DVWA). It does not detect DOM-based XSS where a JavaScript framework (Angular, React, Vue) renders the payload client-side — most modern SPAs use DOM-based patterns. Always test XSS manually in the rendered application. DOM-based XSS detection via Playwright is deferred to v0.3.
- JWT attacks: the JWT check captures bearer tokens and replays token mutations against authenticated endpoints. It only finds targets that accept tampered tokens, such as `alg:none`, weak secrets, or accepted claim tampering. It does not find logic-level JWT authorization flaws.
- SSRF: v0.1 does not have production callback infrastructure wired for real OOB confirmation. SSRF remains manual unless callback infrastructure is explicitly configured and verified.
- Open redirect: only captured redirect-like parameters are tested. If the HAR does not include a redirect parameter, SecScan will not discover one.
- Auth and authz: v0.1 has basic probes, but it does not replace role-matrix testing, IDOR/BOLA review, forced browsing review, or business authorization testing.
- Business logic, CSRF, race conditions, file upload abuse, workflow abuse, payment logic, invite/team logic, tenant isolation, and privilege boundary testing are not covered. These remain fully manual.
- Anything not in the captured HAR is never tested. Coverage equals what the operator browsed and submitted. If you did not visit a page, submit a form, type in a search box, or trigger a workflow, SecScan cannot test it.

Never tell a client "the app is secure" because SecScan came back clean.

## 4. First-Time Setup

These commands assume macOS or Linux and a fresh clone. Run them from a normal terminal.

```bash
git clone <REPO_URL>
cd "Application Security Scanner"
```

Get the repository and enter the project root; all later commands assume this working directory.

```bash
python3 --version
```

Check Python. It must be `3.11.x`, `3.12.x`, or `3.13.x`. Python 3.9 is too old, and Python 3.14 is not supported by the pinned asyncpg stack.

If your system Python is wrong on macOS:

```bash
brew install python@3.12
python3.12 --version
```

Install a supported interpreter and verify it.

If your system Python is wrong on Linux, install Python 3.12 with your distro package manager or `pyenv`, then verify:

```bash
python3.12 --version
```

```bash
python3.12 -m venv .venv
source .venv/bin/activate
```

Create and activate a virtual environment. Activate it in every new terminal before using SecScan; your prompt should show `(.venv)`. If `secscan`, `alembic`, or environment variables seem to "disappear" between sessions, you probably opened a new terminal and did not reactivate/re-export.

```bash
python -m pip install --upgrade pip
pip install -e .
```

Install SecScan and dependencies in editable mode. The repo uses Poetry metadata in `pyproject.toml`, but `pip install -e .` is the actual local setup path documented here.

```bash
playwright install chromium
```

Install the Chromium browser binary. This is separate from the Python package install; the Playwright authentication step fails without it.

```bash
cd docker
docker compose up -d
cd ..
```

Start local infrastructure. Docker Desktop or Docker Engine must already be running. This starts Postgres and an interactsh container; interactsh is optional/unused for normal v0.1 scans.

Quick per-session environment setup:

```bash
export DATABASE_URL="postgresql+asyncpg://secscan:secscan@localhost:5432/secscan"
export INTERACTSH_URL="http://localhost:9000"
```

Set the DB URL for this terminal only. You must run this again in a new terminal.

Permanent/recommended setup:

```bash
cp .env.example .env
set -a
source .env
set +a
```

Create a local `.env` and load it into the current shell. SecScan does not auto-load `.env`; `config.py` and Alembic read real environment variables from the shell.

The Docker database credentials are:

```text
host: localhost
port: 5432
database: secscan
user: secscan
password: secscan
DATABASE_URL=postgresql+asyncpg://secscan:secscan@localhost:5432/secscan
```

```bash
alembic upgrade head
```

Apply the database schema. This creates the tables and must run once before first use.

```bash
secscan --help
```

Verify the CLI is installed and available from the active virtualenv.

```bash
secscan init --target smoke --base-url http://localhost:3000 && secscan ingest --har tests/fixtures/juice_shop_session.har --target smoke
```

Run a smoke test using the bundled HAR fixture. This verifies the CLI, DB connection, migrations, HAR parser, and endpoint normalizer before you touch a real target.

If something fails, see Troubleshooting below.

## 5. Operator Workflow

### Prerequisites

Before scanning a target, you need:

- Docker running for local Postgres.
- Python 3.11, 3.12, or 3.13.
- The virtualenv activated with `source .venv/bin/activate`.
- Playwright Chromium installed with `playwright install chromium`.
- `DATABASE_URL` exported or loaded from `.env`.
- Written authorization for the target and scan rate.

Start the database:

```bash
source .venv/bin/activate
set -a
source .env
set +a
cd docker
docker compose up -d
cd ..
```

This activates the tool, loads environment variables, and starts Postgres.

### Create a Target

```bash
secscan init --target acme-fintech --base-url https://app.acme.example
```

This creates:

```text
targets/acme-fintech/secscan.toml
targets/acme-fintech/auth_script.py
```

Edit `targets/acme-fintech/secscan.toml` for the real base URL and conservative scan settings.

### Write `auth_script.py`

The template is copied from `templates/auth_script.py.template`. SecScan opens a Playwright page, calls your `authenticate(page, config)` coroutine, then captures cookies, localStorage, sessionStorage, and bearer tokens.

Simple username/password example:

```python
async def authenticate(page, config):
    base_url = config.target.base_url
    await page.goto(f"{base_url}/login", wait_until="networkidle")
    await page.fill('input[name="email"]', "pentest-user@example.com")
    await page.fill('input[name="password"]', "REPLACE_WITH_TEST_PASSWORD")
    await page.click('button[type="submit"]')
    await page.wait_for_load_state("networkidle")

    if "login" in page.url.lower():
        raise RuntimeError(f"Login failed; still on {page.url}")
```

Cookie fallback example for OTP/CAPTCHA-heavy targets:

```python
async def authenticate(page, config):
    await page.context.add_cookies([
        {
            "name": "session",
            "value": "PASTE_SESSION_COOKIE",
            "domain": "app.acme.example",
            "path": "/",
            "secure": True,
            "httpOnly": True,
        }
    ])
    await page.goto(f"{config.target.base_url}/dashboard", wait_until="networkidle")
    if "login" in page.url.lower():
        raise RuntimeError("Injected cookie is expired or invalid.")
```

Use dedicated test accounts. Do not put real client production credentials into commits.

### Capturing a Good HAR — Coverage Determines Findings

**Golden rule: SecScan only tests inputs and endpoints that appear in the HAR. If a URL was not visited, a button was not clicked, a form was not submitted, or a search box was not typed into with a real value, SecScan cannot find a vulnerability there.**

During HAR capture, the operator must actively exercise the application, not just navigate around it:

- Log in fully and reach the authenticated state.
- Visit every distinct page and route in the application.
- Submit every form with real non-empty values. Do not just open the form; actually type and submit it.
- Type non-empty queries into every search box and submit.
- Trigger every filter, sort, dropdown, and toggle.
- Click into detail views, modals, and tabs.
- Visit admin areas if the test account has access.
- Trigger error states with wrong inputs and invalid IDs so error paths are captured.
- Perform create, update, and delete actions on test data where safe.
- Hit user profile, settings, exports, downloads, and any "view as" toggles.
- Switch between any roles or tenants the test account can access.

Empty values matter. If the operator visits a search page but never types a query, the search parameter will be captured as empty, and SecScan v0.1 may classify it as not-worth-injecting. Always submit real values.

Chrome HAR export:

1. Open DevTools with `Cmd+Opt+I` on macOS or `F12`.
2. Open the Network tab.
3. Tick `Preserve log`.
4. Browse the app using the checklist above.
5. Right-click any network entry.
6. Select `Save all as HAR with content`.
7. Save it to `targets/<target>/session.har`.

Firefox HAR export:

1. Open DevTools.
2. Open the Network tab.
3. Click the gear/settings icon.
4. Enable `Persist Logs`.
5. Browse the app using the checklist above.
6. Right-click a network entry.
7. Select `Save All As HAR`.
8. Save it to `targets/<target>/session.har`.

A thorough HAR capture for a real engagement typically takes 30-60 minutes of active browsing. Less time usually means less coverage.

If SecScan's report is unexpectedly empty or thin, check HAR coverage first. Re-capture with more active interaction. This is far more often the cause than a tool bug.

Crawler note: v0.2 can discover pages and exercise inputs automatically for supported targets. HAR quality still matters when the crawler is a poor fit, especially for complex workflows and large-platform SPAs.

### Capture a HAR

Export the HAR from your browser and save it under the target directory, for example:

```text
targets/acme-fintech/session.har
```

### Ingest

```bash
secscan ingest --har targets/acme-fintech/session.har --target acme-fintech
```

This parses the HAR, deduplicates endpoints, classifies parameters, and writes endpoints to Postgres.

### Run

Start conservatively on real targets:

```bash
secscan run --target acme-fintech --checks sqli,headers,data --rate-limit 2 --max-concurrency 2
```

Run all checks when scope and rate are approved:

```bash
secscan run --target acme-fintech --checks sqli,xss,ssrf,authz,redirect,data,headers,auth,jwt --rate-limit 2 --max-concurrency 2
```

The CLI exits with code `1` if high or critical findings are produced. That is expected and useful for automation; it does not mean the scan crashed.

### Report

```bash
secscan report --target acme-fintech --format html --output acme-fintech-secscan-report.html
```

or:

```bash
secscan report --target acme-fintech --format json --output acme-fintech-secscan-report.json
```

Read the report as triage input. Each finding includes evidence, a PoC-style request, remediation guidance, and a manual verification playbook. Confirm findings by hand before client reporting.

## v0.2 Crawler Workflow (alternative to HAR capture)

Instead of capturing a HAR manually, v0.2 can crawl the target automatically. The crawler authenticates using the same `auth_script.py`, navigates the rendered application, and writes to the same endpoint graph the HAR ingest produces. Downstream scan commands are unchanged.

### When to use the crawler vs HAR

Use `--crawl` when:

- The target is a standard SPA or server-rendered app with accessible navigation links and forms.
- You want broader coverage without spending 30-60 minutes manually browsing.
- Running the SecComply CRM, a GRC dashboard, or similar internal tooling.

Use `--har` when:

- The target has complex auth flows (MFA, SSO, CAPTCHA) that the crawler cannot complete.
- The target has large-platform SPA navigation (GitHub, Google Workspace) where the crawler produces thin coverage.
- You need precise control over exactly which workflows are tested (e.g. a specific multi-step checkout flow).
- The crawler crashes or times out on the target — fall back to HAR, it always works.

### Crawl commands

Init (same as before):

```bash
secscan init --target acme-fintech --base-url https://app.acme.example
```

Write `auth_script.py` (same as before — the crawler reuses it).

Ingest via crawler instead of HAR:

```bash
secscan ingest --crawl --target acme-fintech
```

Run capability-only check first (no injection payloads):

```bash
secscan run --target acme-fintech --crawl-only
```

This navigates and builds the endpoint graph without sending any vulnerability payloads. Use this for third-party targets where you have a legitimate account but no written authorization for full scanning.

Run full scan (requires `authorized_hosts` entry in `secscan.toml`):

```bash
secscan run --target acme-fintech \
  --checks sqli,xss,ssrf,authz,redirect,data,headers,auth,jwt \
  --rate-limit 2 --max-concurrency 2
```

### Crawler configuration (`secscan.toml` `[crawler]` section)

```toml
[crawler]
max_depth = 3              # how many link-hops from base_url
max_pages = 50             # hard page cap
max_time_seconds = 1800    # 30-minute wall-clock limit
forced_browsing_enabled = true
authorized_hosts = ["localhost", "127.0.0.1"]
# Add your target's hostname here before running full scans:
# authorized_hosts = ["localhost", "app.acme.example"]
```

### Known crawler limitations

- React/Angular SPA navigation: the crawler follows declarative links and form submissions. JavaScript-only navigation (modal-gated routes, drag-and-drop, infinite scroll) is not reached. If the crawler produces fewer than 10 endpoints on a rich SPA, fall back to HAR.
- Large-platform SPAs (GitHub, Google Workspace): crawler produces thin coverage (1-9 endpoints) despite successful authentication. Use HAR for these targets.
- Ant Design / Material UI inputs: some React component library inputs require `page.type()` with keystroke delay in the `auth_script.py` rather than `page.fill()`. If auth fails on a React app, try replacing `page.fill()` with `page.click()` + `page.type()` with `delay=50`.
- Application-side effects: authenticated crawling may trigger server-side writes (audit logs, pipeline bootstraps, notifications) as a side effect of normal page navigation. Always use a dedicated test account and inform the client.
- `authorized_hosts` enforcement: full scan mode (`--checks`) against a hostname not in `authorized_hosts` is blocked by default. Add the hostname explicitly before scanning.

## 6. Where the Operator Takes Over

After SecScan runs, manual VAPT begins.

- Verify every SecScan finding manually in Burp Repeater, browser DevTools, or a controlled script.
- Confirm exploitability, impact, affected roles, and affected tenants.
- Remove false positives before adding anything to a client report.
- Re-run suspicious findings with a clean baseline to rule out caching, WAF behavior, stale sessions, or generic error pages.
- Manually test XSS in the rendered SPA.
- Manually test business logic and workflow abuse.
- Manually test IDOR/BOLA with a proper role/user matrix.
- Manually test CSRF where relevant.
- Manually test race conditions.
- Manually test file upload handling.
- Manually test SSRF with approved callback infrastructure.
- Manually test open redirects beyond captured parameters.
- Manually test tenant isolation, payment flows, invitation flows, approvals, exports, admin actions, and audit-log bypasses.
- Review authentication and session management behavior manually.

Do not paste raw SecScan output into a client report without human verification.

## Known Limitations and Operator Warnings

### Authenticated crawling may trigger application-side effects

The crawler navigates the target app as an authenticated user. Some applications trigger server-side effects during normal page loads -- including audit log entries, pipeline bootstraps, webhook triggers, notification events, or state initialization calls. These are not caused by injection payloads; they are caused by the app itself responding to authenticated navigation.

This was observed during Phase 5 Tier 1 validation: a Next.js CRM issued a POST to a pipeline-initialization endpoint during a crawl-only run with no scan checks active.

Operator guidance:

- Always use a dedicated test account that the client expects to generate activity.
- Inform the client before crawling that authenticated navigation will produce entries in their access logs and audit trails.
- Review the crawl summary log for any unexpected POST requests captured during the crawl -- these indicate app-side writes triggered by navigation.
- If the client's app has sensitive pipeline or workflow triggers, confirm with them which routes to avoid before crawling. Add those routes to the `[crawler]` `blocklist_extra` in `secscan.toml`.

### GitHub-style large-platform SPAs produce thin coverage

Large SaaS platforms (GitHub, Google Workspace, and similar) use JavaScript-heavy rendering patterns where the crawler's declarative navigation strategy captures only the initial page load. Depth-3 traversal on these targets typically yields fewer than 10 unique endpoints. This is a known v0.2 limitation -- not a bug.

For these targets, HAR-based ingest (`secscan ingest --har`) remains the recommended approach. The crawler is most effective on application-style SPAs (dashboards, CRMs, fintech apps) rather than large platform-style products.

### Role-identical endpoint graphs

When crawling an app with multiple roles (e.g. student and admin), the crawler may produce identical or near-identical endpoint graphs if role-gated UI routes are only accessible through interactions the Phase 3 crawler cannot reach (modal-gated content, role-switch flows, deep navigation trees). Verify role coverage manually for high-value authorization testing.

## 7. Safety and Scope

Only scan targets where SecComply has explicit written authorization. Confirm the allowed domains, environments, test accounts, dates, time windows, and scan rate before running the tool.

The shipped defaults are deliberately conservative for unknown production targets:

```toml
max_concurrency = 2
rate_limit_rps = 2
max_retries = 2
```

An operator may raise them via `targets/<target>/secscan.toml` or the `--rate-limit` / `--max-concurrency` flags only for a target known to tolerate load, such as a local test instance or staging environment with client sign-off:

```bash
secscan run --target acme-fintech --checks sqli,headers,data --rate-limit 5 --max-concurrency 5
```

Use higher rates only when the client has explicitly approved them. Never scan a target you do not have permission to scan.

## 8. Troubleshooting

### `DATABASE_URL is not set`

You opened a new terminal or did not load `.env`.

```bash
source .venv/bin/activate
set -a
source .env
set +a
echo "$DATABASE_URL"
```

### `secscan: command not found`

The virtualenv is not active or the package was not installed.

```bash
source .venv/bin/activate
pip install -e .
secscan --help
```

### Postgres connection fails

Docker is not running, the containers are down, or port 5432 is occupied.

```bash
cd docker
docker compose ps
docker compose up -d
cd ..
```

Verify the DB URL:

```bash
echo "$DATABASE_URL"
```

Expected:

```text
postgresql+asyncpg://secscan:secscan@localhost:5432/secscan
```

### `alembic upgrade head` fails

Usually Postgres is not running or `DATABASE_URL` is missing.

```bash
source .venv/bin/activate
set -a
source .env
set +a
cd docker
docker compose up -d
cd ..
alembic upgrade head
```

### Playwright authentication fails

Chromium may not be installed, or `auth_script.py` may not actually log in.

```bash
playwright install chromium
```

Then inspect and run through the logic in:

```text
targets/<target>/auth_script.py
```

Make sure selectors match the real app, test credentials are valid, OTP/CAPTCHA paths are handled, and the script raises a clear error if login fails.

### Wrong Python version

Check:

```bash
python --version
python3 --version
python3.12 --version
```

Use Python 3.11, 3.12, or 3.13 only. Recreate the virtualenv with a supported interpreter:

```bash
deactivate 2>/dev/null || true
rm -rf .venv
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e .
playwright install chromium
```

### Stale endpoints from a previous target or bad HAR

For a disposable local/dev target, remove the target and re-ingest:

```bash
PGPASSWORD=secscan psql -h localhost -p 5432 -U secscan -d secscan -c "DELETE FROM targets WHERE name = 'acme-fintech';"
secscan init --target acme-fintech --base-url https://app.acme.example
secscan ingest --har targets/acme-fintech/session.har --target acme-fintech
```

Only do this on your local scanner database. It deletes that target's stored endpoints, scans, sessions, and findings.

### The report is clean but you expected findings

Check the HAR first. If the endpoint, form field, search parameter, JSON body field, or workflow is not in the HAR, SecScan did not test it.

Re-capture while actively using the feature, then re-ingest and re-run.

## 9. Current Status and Roadmap

SecScan v0.1 was the captured-surface scanner: it tested what the operator browsed and submitted via a manual HAR. SecScan v0.2 adds an authenticated Playwright crawler that discovers pages and exercises inputs automatically, unlocking broader API coverage and server-side reflected XSS detection. v0.3 is planned to add DOM-based XSS detection via Playwright, OOB callback infrastructure for SSRF, new vulnerability classes (GraphQL, XXE, JWT logic flaws), and improved JS-driven SPA navigation depth for large-platform targets.
