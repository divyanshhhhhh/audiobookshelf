# Pipeline Maintenance Guide

## 1. Adding a new security test case
1. Identify the threat (map it back to a Lab 2–5 threat model entry).
2. Choose the right stage:
   - Code-pattern issue (e.g., new injection risk) → add a Semgrep rule under
     `--config` in `security-pipeline.yml`, or a custom rule in `.semgrep/`.
   - Dependency/CVE risk → already covered automatically by `npm audit` + Trivy;
     no action needed unless you want a stricter severity gate (edit
     `--severity` in the Trivy steps).
   - Endpoint/business-logic risk → add a ZAP scan rule to `.zap/rules.tsv`
     (format: `<rule-id>\tIGNORE|WARN|FAIL\t<url-regex>`), or write a dedicated
     API test (e.g., a `curl`/Postman/newman script) as a new job step.
3. Re-run the pipeline locally first (self-hosted runner or `act`) before pushing.
4. Document the new test in the "Test Case Justification" section of the report.

## 2. Updating tools and configurations
- **Semgrep rulesets**: update via `--config` flag or `.semgrep.yml`; check
  `semgrep --version` monthly, rules update independently of the binary.
- **Trivy DB**: auto-refreshes on each run (`trivy image` pulls latest vuln DB);
  force refresh with `trivy image --clear-cache` if scans seem stale.
- **ZAP**: pin `zaproxy/action-baseline` to a specific version tag; bump
  deliberately and re-test, since rule sets can change scan behavior.
- **Base image (`advplyr/audiobookshelf:latest`)**: pin to a specific version
  tag in `docker-compose.hardened.yml` once you've validated it, rather than
  tracking `:latest`, so upgrades are a deliberate, tested step.

## 3. Interpreting and acting on reports
| Report | Where | How to read it |
|---|---|---|
| `semgrep-results.sarif` | GitHub Actions artifact | Each `result` = one finding; `level: error` = fix before merge, `warning` = triage |
| `trivy-image.json` / `trivy-fs.json` | artifact | Filter `Severity: CRITICAL/HIGH` first; `FixedVersion` field tells you the safe upgrade |
| `npm-audit.json` | artifact | `advisories` array; run `npm audit fix` for auto-fixable issues |
| ZAP scan output | workflow log / uploaded HTML | Alerts grouped by risk (High/Medium/Low); cross-reference against OWASP Top 10 IDs |
| `trivy-post-deploy.txt`, `nmap-post-deploy.txt` | produced by validation script | Confirms the deployed instance, not just the built image, is clean and only intended ports are open |

Triage rule of thumb: **CRITICAL/HIGH → open a GitHub issue same day; MEDIUM →
batch into next maintenance cycle; LOW/INFO → log and revisit quarterly.**

## 4. Maintaining compatibility with future Audiobookshelf versions
- Before bumping the pinned image version, run the full pipeline against the
  new tag on a branch first (`docker-compose.hardened.yml` image tag change only).
- Watch the upstream `advplyr/audiobookshelf` release notes for changed config
  paths, new env vars, or endpoint changes — update `Caddyfile` `@adminPaths`
  and healthcheck path if the app's routes change.
- Re-run `post-deploy-validate.sh` after every version bump; treat any new
  FAIL as a blocker, not a warning.

## 5. Merge gating: required checks and the baseline ratchet

### Required status checks on `master`

`master` requires a pull request, and these four checks must pass before the
merge button is enabled. The names must match the job `name:` values in
`.github/workflows/security-pipeline.yml` character for character:

| Required check | Job |
|---|---|
| `Static Code Analysis (SAST)` | `static-analysis` |
| `Open Source Dependency & Image Scanning (SCA)` | `dependency-scan` |
| `Application Security Test Cases` | `security-tests` |
| `Security Gate` | `security-gate` |

Two jobs are deliberately **not** required:

- **Developer Notification** runs `if: always()`, so it reports success even
  when the stages before it failed. Requiring it would add a check that can
  never block anything, which makes the protection look stronger than it is.
- **Automated Secure Deployment** is skipped on `pull_request` events by
  design. A required check that never runs on pull requests leaves them
  permanently pending and unmergeable.

To review or change the rule: **Settings > Rules > Rulesets** on the
repository, or `gh api repos/:owner/:repo/rulesets`.

### The two baselines, which do different jobs

| File | Scope | Gate behaviour |
|---|---|---|
| `security-tests-baseline.json` | Named test IDs known to fail | A failing test **not** listed here is a regression and fails `Application Security Test Cases` |
| `security-baseline.json` | Numeric finding counts | A count **exceeding** the recorded number fails `Security Gate` |

Both are delta gates, not absolute ones. The codebase currently carries 65
HIGH/CRITICAL image CVEs, 25 npm audit findings and six failing security tests
against unpatched upstream code. An absolute gate would be red on every run
forever, and a check that can never pass gets bypassed, disabled or merged
around, which leaves less protection than no gate at all. Blocking only on
"worse than last time" is a standard that can actually be held.

### The ratchet rule

**Lower a baseline number in the same commit as the fix that lowers it.**

That way the standard only ever moves downward, and it cannot quietly drift
back up: raising a number is a visible diff in a pull request that a reviewer
has to approve, with a reason attached. If the numbers were updated separately,
or refreshed automatically from the latest run, the baseline would simply track
whatever the codebase does and stop being a standard at all.

The same applies to `security-tests-baseline.json`: when a test starts passing,
the runner prints a note asking for its entry to be removed, and that removal
belongs in the commit that fixed it. After removal, any regression fails CI.

To re-record the numeric baseline after a deliberate change, read them from a
completed run rather than from memory:

```bash
gh run download <run-id> -D /tmp/base
jq 'length' /tmp/base/sast-reports/gitleaks-report.json
jq '.metadata.vulnerabilities.critical, .metadata.vulnerabilities.high' /tmp/base/sca-reports/npm-audit.json
jq '[.Results[]?.Vulnerabilities[]?] | length' /tmp/base/sca-reports/trivy-image.json
```

### Strict mode for the security tests

`scripts/security-tests.sh` takes `SECTEST_STRICT`:

| Value | Behaviour |
|---|---|
| unset or `0` (default) | Fails only on a regression or an error |
| `1` | Fails if **any** test is failing or errored, and lists the failing IDs |

CI uses the default. Strict mode is for a release candidate, or for a fork
where the underlying defects have been fixed and the expected state is genuinely
zero failures. It is not the default because six tests fail today, so a strict
default would block every merge and would also stop the deploy job, which
depends on the tests, from ever running, removing the deployment evidence the
gate exists to protect.

```bash
SECTEST_STRICT=1 ./scripts/security-tests.sh http://localhost:18081
```

### Semgrep results in the Security tab

The SAST job publishes `semgrep-results.sarif` to GitHub code scanning, so
findings appear as inline annotations on the changed lines of a pull request,
and GitHub distinguishes alerts that are new in the branch from ones already
present on `master`. This needs `security-events: write`, which is set at the
workflow level. Code scanning is free on public repositories.

## 6. Developer engagement record
Log every interaction with the Audiobookshelf maintainers/community here (link
to Discussion threads, PR comments, Discord messages — redact usernames/emails
per submission rules) as ongoing evidence of the "Developer Reuse Evidence"
rubric item:

| Date | Channel | Summary | Link |
|---|---|---|---|
| | GitHub Discussions | | |
| | PR review comment | | |
