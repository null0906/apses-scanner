# SecScan v0.2 — BRD + FRD

- Owner: Atharva Sardesai
- Status: Draft, locked pending validation gate setup
- Capacity: ~20 hrs/week (same as v0.1)
- Build window estimate: 8-10 weeks
- Predecessor: v0.1 shipped, in colleague use, see `SECSCAN_v0.1_BRD_FRD.md`

## 0. What v0.2 is

SecScan v0.2 adds an authenticated crawler that drives a real browser with Playwright against a target, navigates the rendered application, exercises forms and inputs, and produces the same kind of endpoint graph that v0.1 currently requires the operator to hand-capture as a HAR. The crawler is the single feature in v0.2. It unlocks XSS-in-SPA, redirect parameter discovery, deeper authz exploration, and broader application coverage. Everything else from the original roadmap, including new vuln classes, OOB infra, and JS bundle parsing, defers to v0.3+.

## 1. Business rationale

The gap v0.2 closes is now clear: v0.1 only tests inputs and endpoints that appear in the HAR. The audit and live Juice Shop runs confirmed this is the dominant limitation. XSS was silent because the search box was not reliably exercised in the rendered SPA. Multiple authz/auth probes were inert because captured inputs did not exercise the right paths.

A crawler is the correct answer because the industry already solved this problem with browser-driven crawling. Burp Pro, ZAP, Acunetix, Veracode DAST, and similar tools all use rendered navigation to discover the real application surface. This is known-good engineering, not novel research. The only choice is scope.

v0.2 is not autonomous business logic testing, not AI-driven vulnerability discovery, not new vulnerability classes, and not a UI. v0.2 is one thing: replace "operator captures HAR" with "crawler captures the same shape of data, only better."

The business value is practical: fewer missed pages, fewer missed inputs, more reliable findings, and less dependence on whether the operator remembered to type into every search box during HAR capture.

## 2. Why "v0.1 + XSS" is the wrong framing

The XSS check in v0.1 is conceptually correct. XSS did not fire because the JSON API surface generally does not reflect executable payloads; the Angular SPA at `/#/search` does after data is rendered into the browser. Once the crawler navigates the rendered page and submits payloads through the actual search input, the existing XSS logic can observe the browser-visible behavior.

Building the crawler is therefore the XSS work for v0.2. No XSS-specific feature work is in scope.

The same logic applies to redirect, authz forced-browsing, and partially to auth. The crawler discovers redirect parameters, unlinked routes, stateful UI paths, and session-dependent endpoints. Coverage improvement across multiple checks is the consequence. The crawler is the feature.

## 3. Phase 0 — revised validation approach

The original plan was 2 weeks of real-client engagement evidence before locking v0.2 scope. After 2 weeks of business-development effort, no real VAPT engagements were available within the v0.2 timeline. Phase 0 is revised to a realistic-target validation gate instead.

- Primary validation target: OWASP crAPI, a deliberately-vulnerable fintech-style app with proper auth flows, JWTs, multiple roles, and complex multi-step workflows. This replaces Juice Shop as the realism bar for v0.2.
- Secondary validation: at least one real production SaaS account the team has legitimate access to, such as an owned GitHub org, Notion workspace, Linear account, or similar, in crawler-only read-only mode.
- v0.2.1 is expected as a reactive patch release after the first real client engagement whenever that lands. This is planned, not a failure mode.
- A colleague feedback template is still distributed, framed as: use this on the first real target you get, even if post-v0.2.

## 4. v0.2 feature scope

### 4.1 The crawler — the only real feature

A new module `secscan/crawler/` will:

1. Bootstrap an authenticated session using the existing Playwright `auth_script.py` mechanism. No change to v0.1's auth model.
2. Navigate from the target's `base_url`. Render the SPA fully. Wait for network idle.
3. Extract interactable surface from the rendered DOM: links, forms, buttons, dropdowns, tabs, and route-changing controls. Not raw HTML; what a user could actually click or type into.
4. Exercise inputs with benign test values such as text -> `secscan_test`, number -> `1`, email -> `test@example.com`. Submit forms where safe.
5. Capture all network traffic through Playwright request events. Every XHR, fetch, and document request the SPA fires becomes an endpoint candidate in the shape v0.1 HAR ingest expects.
6. Recursively crawl newly discovered pages up to configurable depth, default 3.
7. Respect scope: only crawl within the target's base URL domain. Never follow external links.
8. Respect rate limits using the same `RateLimiter` infrastructure as the scan, so a crawl cannot hammer a target.
9. Output to the existing endpoint graph by writing directly to the same `endpoints` table that HAR ingest currently writes to. Downstream checks should not need architectural changes.

### 4.2 Forced browsing / wordlist discovery

Add a small forced-browsing pass with a short wordlist of common paths such as `/admin`, `/api`, `/swagger.json`, `/.git/config`, `/health`, `/debug`, `/.env`, and `/api-docs`. Discovered endpoints feed the same graph. Keep the list small, roughly 50 entries. Larger wordlists are v0.3.

### 4.3 Crawler-only mode and ethical scope enforcement

The crawler must support a `--crawl-only` flag that disables all scan checks and only produces an endpoint graph. This is required for:

- Capability validation on third-party authenticated apps where the operator has a legitimate account but no authorization to send injection payloads.
- Any first-time scan of an unknown target as a safe default.

When the target hostname is not on a configured "owned infrastructure / authorized targets" allowlist, `--crawl-only` must be the enforced default. Full scan mode against third-party hosts must require an explicit override flag and a config-file allowlist entry. This is a safety mechanism, not a convenience.

### 4.4 What's deliberately NOT in v0.2

- No JS bundle parsing for hidden endpoints. That is v0.3.
- No new vuln classes. The 9 v0.1 checks are the v0.2 checks.
- No OOB callback infrastructure for SSRF. That is v0.3.
- No business logic / IDOR / BOLA testing primitives. Those are v0.4+.
- No web UI. CLI remains the operator interface.
- No standalone crawler product. Crawling is an ingest option: `secscan ingest --crawl --target <name>`.

## 5. Success metrics

v0.2 ships when all are true:

1. Crawler runs end-to-end on Juice Shop, populating the endpoint graph without operator-supplied HAR.
2. XSS fires on Juice Shop search as a consequence of the crawler typing into the box. If this does not happen, the crawler is not working as intended.
3. At least 50% more endpoints are discovered than the manual HAR captured. Juice Shop manual HAR had roughly 14 endpoints; crawler should find 25+.
4. Crawler completes capability validation on Tier 1 authenticated public apps in Section 5.5 without crashing.
5. Crawler + full scan completes on crAPI and surfaces at least one real finding v0.1's HAR approach would have missed.
6. No regression in v0.1 findings. SQLi, headers, and data counts on Juice Shop remain stable.

## 5.5. Validation tiers

All three tiers must pass before v0.2 ships. Tier 1 runs first as an early gate. If it fails, integration work pauses until the crawler can navigate authenticated public apps cleanly.

### Tier 1 — Crawler-only on authenticated public apps (CAPABILITY VALIDATION)

Run only the crawler component, with no scan checks and no injection payloads, against 3-5 authenticated public apps where the operator has a legitimate account and is scanning only their own data. Examples include an owned GitHub org, owned Notion workspace, owned Linear account, own Gmail account in read-only mode, and a Netflix account in browse-only mode.

Mode: crawler navigates only. No scan checks run. No payloads are sent. The output is an endpoint graph for inspection. This is a navigation capability test, not a vulnerability test.

Validates: real login flow including MFA, OAuth, and CAPTCHA prompts; real session expiry behaviour; anti-bot tolerance; deep SPA navigation; scope enforcement on production-grade apps; and performance under real network conditions.

Exit criterion: crawler completes a depth-3 traversal on at least 3 of the 5 targets without crashing, without triggering account blocks, and produces a sensible endpoint graph that stays within the target's domain.

Legal/ethical line: crawler must be invoked with a flag that explicitly disables all scan checks for this tier. We will only validate navigation capability against third-party apps, never injection payloads. The flag is hard-required when the target hostname is not a configured "own infrastructure" target.

### Tier 2 — Full pipeline on Juice Shop (REGRESSION + XSS PROOF)

Crawler replaces HAR ingest. Full scan with all 9 checks runs. v0.1 findings on Juice Shop reproduce. XSS now fires on `/#/search` because the crawler typed into the search box.

Exit criterion: all v0.1 finding counts reproduced, plus at least 1 XSS finding on the search input.

### Tier 3 — Full pipeline on SecComply-owned infrastructure (REAL VALIDATION)

Crawler + full scan runs against the SecComply staging or demo app, with Sanil's explicit sign-off. This is the closest thing to a real client engagement available within the v0.2 timeline. In addition, run one full pipeline against OWASP crAPI for vuln-detection coverage on a realistic-shape fintech-style target.

Exit criterion: crawler completes both runs without crashing, produces endpoint graphs, and finds at least 1 real finding on each that v0.1's HAR approach would have missed.

## 6. Scope discipline

The single biggest predictor of whether v0.2 ships is whether we resist adding things to it mid-build.

- No new checks during v0.2 build. If colleague feedback or a validation tier reveals a needed new check, it goes on the v0.3 backlog.
- No detection-quality tuning during v0.2 build unless a regression blocks crawler validation. Existing checks are otherwise frozen.
- No infrastructure expansion. No Kubernetes, no new database, no message queue. v0.1 architecture plus one crawler module.
- No re-platforming. Python + Playwright + httpx + Postgres stays.
- A 20 hrs/week build can produce one focused feature in 8-10 weeks. It cannot produce that feature plus three others.

## 7. Safety and Scope

### Legal and ethical scope

SecScan's full scan mode, meaning any `--checks` invocation that sends payloads, is only authorized against:

1. Targets where the operator's organization has explicit written client authorization.
2. Deliberately-vulnerable training apps such as Juice Shop, crAPI, DVWA, and similar apps running locally or on infrastructure the operator controls.
3. SecComply-owned infrastructure with internal sign-off.

Crawler-only mode, using the `--crawl-only` flag, is acceptable against any target where the operator has a legitimate account and is browsing only their own data, in read-only navigation. The default for any third-party authenticated target is crawler-only.

Full scan mode must not be used against third-party authenticated targets unless the target is explicitly in the configured authorized-target allowlist and the operator has written authorization. If there is uncertainty, use crawler-only mode or do not run SecScan.

### Operational safety

- The crawler must inherit the v0.1 conservative rate limits and retry behavior.
- Crawling must stay inside the configured target domain.
- Destructive-looking controls and routes must be blocked by default, including delete, remove, cancel, destroy, deactivate, and irreversible workflow actions.
- Operators must use test accounts and test data whenever possible.
- Any validation on public SaaS accounts must be read-only navigation only.

## 8. Architectural sketch

```text
v0.1 path:
  auth_script.py + HAR file
      -> session bootstrap
      -> HAR ingest / normalizer
      -> endpoints table
      -> ReplayEngine
      -> 9 checks
      -> findings
      -> reports

v0.2 additive path:
  auth_script.py + base_url
      -> session bootstrap
      -> Playwright crawler
      -> rendered DOM interaction
      -> network capture
      -> endpoints table
      -> ReplayEngine
      -> 9 checks
      -> findings
      -> reports
```

`secscan ingest --har <file>` still works for targets where a HAR is preferred. `secscan ingest --crawl --target <name>` runs the crawler. Both write to the same endpoint table. The downstream pipeline is unchanged.

## 9. Build plan (provisional, 8-10 weeks at 20 hrs/wk)

| Phase | Weeks | Deliverable | Gate |
| --- | --- | --- | --- |
| Phase 0 | 1 week | crAPI + own SaaS account access provisioned; colleague feedback template distributed | Targets reachable; allowlist configured |
| Phase 1 | 2 weeks | Crawler skeleton: Playwright launch, auth bootstrap reuse, page navigation, network capture into existing endpoint table | Crawl Juice Shop homepage, capture XHR calls, store in DB |
| Phase 2 | 2 weeks | DOM extraction + form/button interaction with safe benign values + destructive-action blocklist | Crawler types into Juice Shop search, submits, captures resulting request; refuses delete-shaped buttons |
| Phase 3 | 2 weeks | Recursive navigation + depth limiting + scope enforcement + URL deduplication + crawl time/page caps | Crawler visits Juice Shop products list, follows product detail, captures routes, terminates cleanly |
| Phase 4 | 1 week | Forced-browsing wordlist + `--crawl-only` flag + allowlist enforcement | Crawler discovers `/api-docs` or equivalent unlinked endpoint; `--crawl-only` enforced on non-allowlist hostnames |
| Phase 5 | 1 week | Tier 1 capability validation on 3-5 authenticated public apps in crawl-only mode | Passes Section 5.5 Tier 1 |
| Phase 6 | 1 week | Tier 2 + Tier 3 integration + colleague feedback incorporation | XSS fires on Juice Shop search; crAPI run finds real findings; SecComply staging run with Sanil sign-off completes |

Each phase has buffer inside the 8-10 week range. Phase 2 and Phase 6 are the most likely to slip.

## 10. Risks

| Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- |
| Form interaction fails on complex SPAs | High | High | Start with Juice Shop; escalate to crAPI only after Juice Shop works |
| Crawler triggers destructive actions | Medium | High | Block destructive verbs and labels; configurable per-target denylist |
| Session expires mid-crawl | High | Medium | Reuse v0.1 session keeper |
| Crawl never terminates | Medium | Medium | Depth limit default 3, time limit default 30 min, URL dedupe, max-page cap |
| Real targets have bot detection or CAPTCHA | Medium | High | v0.2 does not bypass anti-bot; operator falls back to HAR mode |
| Operator runs full scan against unauthorized third-party target | Medium | Critical | `--crawl-only` default for non-allowlist hosts; allowlist requires explicit config |
| Scope creep into new checks or XSS tuning | High | Critical | Section 6 forbids it; v0.3 backlog captures new work |

## 11. What v0.3+ becomes (for context only, not commitment)

After v0.2 ships and runs on real targets, v0.3 candidates are:

- Detection tuning based on real-target FP/FN reports.
- OOB callback infrastructure for working SSRF.
- New vuln classes: XXE, SSTI, deeper NoSQL, GraphQL, mass assignment, JWT logic flaws.
- JS bundle parsing for endpoint discovery beyond what the crawler clicks.
- Web UI for operating multiple engagements at SecComply scale.

None are committed. v0.3 scope finalizes after v0.2 ships and produces its own real-target memo.

## 12. Sign-off

- [ ] Atharva — primary builder
- [ ] Sanil — informed, with 15-minute sync before v0.2 build starts and explicit sign-off on Tier 3 SecComply staging scan
- [ ] Section 4 scope final lock confirmed before Phase 1 begins

Any change to v0.2 scope after lock requires written re-approval and a corresponding timeline adjustment, same discipline as v0.1.
