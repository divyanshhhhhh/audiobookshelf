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

## 5. Developer engagement record
Log every interaction with the Audiobookshelf maintainers/community here (link
to Discussion threads, PR comments, Discord messages — redact usernames/emails
per submission rules) as ongoing evidence of the "Developer Reuse Evidence"
rubric item:

| Date | Channel | Summary | Link |
|---|---|---|---|
| | GitHub Discussions | | |
| | PR review comment | | |
