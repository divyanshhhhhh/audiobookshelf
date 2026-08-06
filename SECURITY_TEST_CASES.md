# Security test cases

Automated security regression tests for Audiobookshelf, run by the
`Application Security Test Cases` job in
`.github/workflows/security-pipeline.yml` and implemented in
`scripts/security-tests.sh`.

Reference framework: **OWASP Web Security Testing Guide v4.2, chapter 4**.
Each test names the subchapter it derives from.

> **Note on lab traceability.** Each test below records the group vulnerability
> report ID it comes from (V-01, V-04, V-05, V-09, V-14), which is the
> authoritative link. Where a specific Lab number is cited, confirm it against
> the group's own lab submissions before the final report goes in; the finding
> IDs are certain, the lab numbering is the group's own record.

---

## Why these tests exist

The pipeline already runs Semgrep, ESLint with the security plugin, Gitleaks,
npm audit, Trivy and an OWASP ZAP baseline scan. Those tools are generic. They
recognise categories of defect that look the same in every application, and
they were the only security evidence this pipeline produced before these tests
were added.

What the generic tools actually reported on this codebase:

| Tool | What it found |
|---|---|
| OWASP ZAP baseline | Missing `Sec-Fetch-*`, `Cross-Origin-*` and `Permissions-Policy` headers; CSP wildcard and `unsafe-inline` |
| Semgrep | `express-path-join-resolve-traversal` (12), `express-res-sendfile` (7), mutable GitHub Actions tags (40) |
| Trivy / npm audit | Dependency and base image CVEs |

None of them found that logging out leaves the bearer token valid, that the
media-progress endpoint skips the library access check, or that cover art needs
no session at all. A scanner cannot know what *this* application's
authorization rules are supposed to be. That knowledge came from the group's
own manual testing, and these tests are how that knowledge is preserved and
re-checked on every commit.

## How results are handled

Five of the seven tested behaviours are genuinely broken upstream and remain
unpatched, so those tests fail. They are not weakened to produce a green tick.

- Every result is written to `security-tests-results.json` and uploaded as the
  `security-test-reports` artifact.
- Every result is rendered as a table in the job summary.
- Failure counts feed the notification issue alongside every other scanner.
- `security-tests-baseline.json` records each known-failing ID with a written
  justification.

The job fails when a test fails that is **not** in the baseline (a regression),
or when a test **errors** (the harness could not execute, so its result means
nothing). This is deliberately different from the `|| true` and
`continue-on-error` masking removed from this pipeline earlier: masking made
results disappear, whereas the baseline keeps every result visible and counted
while distinguishing "known and reported" from "newly broken".

When a finding is fixed upstream, its test starts passing and the harness says
so explicitly, prompting removal of the baseline entry so that any later
regression fails the build.

### Strict mode

`scripts/security-tests.sh` reads `SECTEST_STRICT`:

| Value | Behaviour |
|---|---|
| unset or `0` (default) | Exit non-zero only on a regression (a failure not in the baseline) or an error |
| `1` | Exit non-zero if **any** test is failing or errored, listing the failing IDs |

The script prints which mode it ran in on every invocation, so a log never
leaves it ambiguous which standard was applied.

The default is not strict on purpose. Six of the seven tests fail today against
unpatched upstream code, so a strict default would mark every commit red and
block every merge. It would also stop the deploy job, which depends on this one,
from ever running, which would remove the deployment evidence the gate exists to
protect. A check that can never pass is a check people learn to route around.

Strict mode is the right setting for a release candidate, or for a fork where
the underlying defects have been fixed and the expected state is genuinely zero.

### Merge gating

Two separate baselines gate merges into `master`, and they answer different
questions:

| File | Scope | Enforced by |
|---|---|---|
| `security-tests-baseline.json` | Named test IDs known to fail | `Application Security Test Cases` |
| `security-baseline.json` | Numeric finding counts (gitleaks, npm audit, Trivy image, test regressions) | `Security Gate` |

`Security Gate` fails when an observed count **exceeds** the recorded number, so
it blocks changes that make things worse without blocking on the existing
backlog. It prints every check as OK or FAIL with observed versus allowed, so
the reasoning is visible in the log rather than implied by a red X.

Both files ratchet in one direction: **a number is lowered in the same commit as
the fix that lowers it**, so the standard tightens as defects are fixed and
cannot drift back up without a visible, reviewable diff.

The required checks on `master` are `Static Code Analysis (SAST)`,
`Open Source Dependency & Image Scanning (SCA)`,
`Application Security Test Cases` and `Security Gate`. See `MAINTENANCE.md`
section 5 for why Developer Notification and Automated Secure Deployment are
deliberately excluded.

## Test environment

The job starts its own container (`abs-sectest`) from the image built by the
dependency-scan job, on its own network and host port 18081, bootstraps it
through `/init`, and removes it in an `if: always()` teardown. It never touches
the hardened deployment (`abs-hardened`) or the lab evidence containers.

`RATE_LIMIT_AUTH_MAX=5` and `RATE_LIMIT_AUTH_WINDOW=60000` are set on the test
container. These are configuration variables the application already supports.
The test **tunes the rate limiter's configuration, it does not alter its
logic**: the code path exercised is identical to production, only the threshold
and window are smaller so the test completes in seconds rather than grinding
through 40 attempts across ten minutes.

---

## ST-01 Authentication rate limiting is keyed on a spoofable header

- **Group finding:** V-05
- **WSTG:** WSTG-ATHN-03, Testing for Weak Lock Out Mechanism
- **Severity:** High
- **Current status:** Fails (known, baselined)

**What it does.** Sends 12 failed logins with a fixed `X-Forwarded-For` as a
control, then 12 more with the header rotating on each request. It asserts that
a `429` still appears in the rotating phase.

**Why the control matters.** If the limiter were disabled or misconfigured, the
attack phase would return no `429` and would look like a bypass. The control
proves the limiter is active first. If the control produces no `429`, the test
reports `error` rather than `fail`, because its result would otherwise be
meaningless.

**Architecture.** `server/utils/rateLimiterFactory.js` builds an
`express-rate-limit` handler whose `keyGenerator` calls
`requestIp.getClientIp(req)`, which reads client-supplied forwarding headers
before falling back to the socket address. The limiter is attached to
`POST /login` and `POST /auth/refresh` in `server/Auth.js`.

**Result.** Control 7 of 12 rate limited, attack 0 of 12. Each spoofed address
gets its own counter, so brute-force protection is defeated by a header the
attacker sets.

**Risk reduction.** Credential brute-force and password spraying are the
practical entry point for a self-hosted server exposed to a network. This test
holds the line on the one control that makes those attacks expensive, and would
catch a future change that reintroduces header trust.

---

## ST-02 Access tokens survive logout

- **Group finding:** V-04
- **WSTG:** WSTG-SESS-06, Testing for Logout Functionality
- **Severity:** High
- **Current status:** Fails (known, baselined)

**What it does.** Logs in, confirms the access token works, calls
`POST /logout` with both the bearer token and the refresh token, then reuses the
same access token against `GET /api/me`. It asserts `401`.

**Architecture.** `server/Auth.js` `POST /logout` clears the `refresh_token`
cookie and calls `invalidateRefreshToken`, then `req.logout()`. Nothing revokes
the already-issued JWT access token, which remains verifiable until it expires.

**Result.** `GET /api/me` returns `200` after a successful logout.

**Risk reduction.** Logout is the control a user reaches for after using a
shared or possibly compromised device, and the action an administrator takes
when they suspect a token has leaked. If it does not revoke access, it provides
false assurance. This is also the highest-value test for shared-device lab
scenarios, where the whole threat is the next person at the keyboard.

---

## ST-03 Refresh tokens must not authenticate as access tokens

- **Group finding:** V-04 (second half)
- **WSTG:** WSTG-SESS-06, Testing for Logout Functionality
- **Severity:** Medium
- **Current status:** **Passes**

**What it does.** Logs in, then presents the refresh token in the
`Authorization: Bearer` header against `GET /api/me`, asserting rejection.

**Result.** Returns `401`. Token types are correctly separated on the tested
version (2.36.0).

**Why it is kept.** The group's report treated refresh-token confusion as part
of V-04, but it is not reproducible on this version. Recording that honestly
matters: the report should not claim a vulnerability that does not exist. The
test stays in the suite as a regression guard, because token type confusion is
easy to reintroduce when refresh handling is refactored, and this test now
fails loudly if that happens.

---

## ST-04 Uploaded HTML served inline in the application origin

- **Group finding:** V-01
- **WSTG:** WSTG-BUSL-09 (Testing Upload of Malicious Files), WSTG-INPV-02 (Testing for Stored Cross Site Scripting)
- **Severity:** High
- **Current status:** Fails (known, baselined)

**What it does.** As a user whose only permission is `upload` and who can reach
exactly one library, uploads an `.html` file containing a script, triggers a
scan so it becomes a library file, then fetches it and inspects the response
headers. It passes if the content type is not `text/html` **or** if
`Content-Disposition: attachment` is set.

**Architecture.** `MiscController.handleUpload` performs no extension or content
type restriction, writing whatever it receives into the library folder.
`GET /api/items/:id/file/:ino` serves library files with a content type derived
from the file. The sibling route `/file/:ino/download` *does* set an attachment
disposition, which is why the assertion accepts either defence: the safe
behaviour already exists on one route and is simply absent on the other.

**Result.** Served as `Content-Type: text/html; charset=UTF-8` with no
attachment disposition, so the script executes in the server's own origin.

**Risk reduction.** This is stored XSS reachable by the lowest-privilege account
that can upload. In the application's own origin, script can act as any user who
opens the file, including an administrator. Semgrep flagged `express-res-sendfile`
and path handling nearby, but could not determine that the served content was
attacker-controlled and executable; that required exercising the running
application.

---

## ST-05 Media progress bypasses library authorization

- **Group finding:** V-09
- **WSTG:** WSTG-ATHZ-02, Testing for Bypassing Authorization Schema
- **Severity:** Medium
- **Current status:** Fails (known, baselined)

**What it does.** Creates two libraries and a user with access to only the
first. Confirms as a control that `GET /api/items/<item in library B>` is
refused, then writes media progress for that same item and reads it back.

**Why the control matters.** It proves the item really is outside the user's
authorization scope, so a `200` from the progress endpoint is an inconsistency
inside the application rather than a mistake in the fixture.

**Architecture.** Item routes in `server/routers/ApiRouter.js` are bound through
`LibraryItemController.middleware`, which enforces library access. The
`/api/me/progress/*` routes bind straight to `MeController` methods with no
equivalent check.

**Result.** Direct item read returns `403`; `PATCH /api/me/progress/<id>`
returns `200` and the value reads back with the library item id intact.

**Risk reduction.** On a shared server, library separation is the control that
keeps one user's collection private from another. This is an insecure direct
object reference: it confirms which item ids exist and lets a user attach state
to them. It is the same class of defect as the group's other authorization
findings and the one most likely to be reintroduced, since the progress routes
sit outside the middleware that protects everything else.

---

## ST-06 Cover art served without authentication

- **Group finding:** V-14
- **WSTG:** WSTG-ATHZ-04, Testing for Insecure Direct Object References
- **Severity:** Medium
- **Current status:** Fails (known, baselined)

**What it does.** Uploads a cover to an item in the restricted library as an
administrator, then requests that cover with no credentials at all, asserting
`401` or `403`.

**Architecture.** `this.router.get('/items/:id/cover', LibraryItemController.getCover)`
is registered without `LibraryItemController.middleware`, unlike the `POST`,
`PATCH` and `DELETE` handlers on the same path, which all carry it. The omission
is visible in a single line of `ApiRouter.js`.

**Result.** Returns `200` with 420 bytes of `image/webp` to an anonymous client.

**Risk reduction.** Cover art carries title and author information, so anonymous
read access leaks the contents of private libraries to anyone who can reach the
server and guess or harvest an item id. The asymmetry with the other verbs on
the same route makes this a plausible oversight rather than a deliberate
exemption, and therefore worth a permanent regression test.

---

## ST-07 Unhandled rejection in the upload handler terminates the server

- **Group finding:** New, discovered while building ST-04. Not in the original report.
- **WSTG:** WSTG-BUSL-09 (Testing Upload of Malicious Files), WSTG-ERRH-02 (Testing for Stack Traces)
- **Severity:** High
- **Current status:** Fails (known, baselined)

**What it does.** As the low-privilege uploader, posts two files under a single
multipart field name, then polls `/healthcheck` and inspects the container
state. It asserts the server is still running.

**Architecture.** `MiscController.handleUpload` builds its file list with
`Object.values(req.files)`. When two files share one field name, that yields a
single nested array rather than two file objects, so `file.name` is `undefined`,
`sanitizeFilename` returns `false`, and `Path.join` is called with a boolean.
The resulting `TypeError` is thrown inside an unawaited promise, so it surfaces
as an unhandled rejection, which is fatal. The process exits and the container
stops.

**Result.** The upload request never completes, the server stops answering
`/healthcheck`, and the container's `Running` state becomes `false`.

**Risk reduction.** Any authenticated account holding the `upload` permission
can terminate the service with one request, with no special tooling. Semgrep did
flag `express-path-join-resolve-traversal` on this file, so static analysis
pointed at the right function, but it identified the pattern as a traversal risk
and could not show that the reachable consequence was a crash. Confirming that
required sending the request.

**This test must remain last in the suite.** When it fails it does so by killing
the target, so any test after it would report `error` for the wrong reason. The
job's teardown runs unconditionally.

---

## Automated versus manual discovery

| Finding | Found by | Notes |
|---|---|---|
| Dependency and base image CVEs | Automated (Trivy, npm audit) | Continuously, no application knowledge needed |
| Missing security headers, CSP weaknesses | Automated (ZAP baseline) | Generic, and already mitigated at the reverse proxy in `docker/Caddyfile` |
| Unsafe path handling in the upload controller | Automated (Semgrep), impact manual | Semgrep named the function; the crash was only demonstrable at runtime (ST-07) |
| V-05 rate limiter header trust | Manual | Requires knowing the limiter keys on a client-supplied header |
| V-04 logout does not revoke access tokens | Manual | Requires a stateful sequence: login, logout, replay |
| V-01 stored XSS via upload | Manual | Requires a multi-step business flow across two endpoints |
| V-09 media-progress authorization gap | Manual | Requires comparing two endpoints' behaviour for one user |
| V-14 unauthenticated cover access | Manual | Visible in code review, but only confirmable by request |

**Lessons learned.** The scanners were good at breadth and useless at depth.
Every finding that depended on knowing what the application's own rules are
supposed to be, and in particular every authorization and session flaw, came
from manual testing. The value of this job is that it converts that one-off
manual work into something that runs on every commit, which is the only reason
those findings will not silently regress after the group stops testing by hand.

The second lesson is that a test suite asserting secure behaviour against
known-vulnerable software will be red, and that the honest response is a
baseline that keeps the failures visible rather than assertions weakened until
they pass.

---

## Running the tests locally

```bash
docker network create abs-sectest-net
docker run -d --name abs-sectest --network abs-sectest-net -p 18081:80 \
  -e RATE_LIMIT_AUTH_MAX=5 -e RATE_LIMIT_AUTH_WINDOW=60000 \
  <image-built-by-the-pipeline>
./scripts/security-tests.sh http://localhost:18081
docker rm -f abs-sectest && docker network rm abs-sectest-net
```

The target must be a fresh, uninitialised instance the script can bootstrap.
Never point it at the hardened deployment or at the lab evidence containers.
