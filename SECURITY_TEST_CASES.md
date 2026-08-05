# Security test cases

Application-specific security regression tests, run by
`.github/workflows/security-tests.yml` and implemented in
`scripts/security-tests.sh`.

Each test names the OWASP Web Security Testing Guide v4.2 subchapter it derives
from. All results below were observed against **Audiobookshelf 2.36.0**.

---

## Why these exist alongside CodeQL

This repository already runs CodeQL, and static analysis is good at what it
does: it recognises categories of defect that look the same in every codebase.
What it cannot do is know what *this* application's authorization rules are
meant to be.

Running Semgrep's OWASP, JavaScript and Node rulesets over this codebase, plus
an OWASP ZAP baseline scan against a running instance, produced only:

- missing `Sec-Fetch-*`, `Cross-Origin-*` and `Permissions-Policy` headers, and
  CSP weaknesses (ZAP)
- generic pattern matches such as `express-res-sendfile` and
  `bypass-tls-verification` (Semgrep)
- dependency and base image CVEs (Trivy, npm audit)

None of them reported that logging out leaves the bearer access token valid,
that the media progress endpoints skip the library access check applied
everywhere else, or that cover art is served without a session. Those are
statements about intended behaviour, and a scanner has no way to derive them.

The five tests that currently fail were all found by hand. The value of putting
them in CI is that they stay found.

## How results are handled

Some of the tested behaviours are not the secure ones today, so those tests
fail. They are not weakened to make the job green:

- every result is written to `security-tests-results.json` and uploaded as an
  artifact
- every result is rendered as a table in the job summary
- `security-tests-baseline.json` lists each currently-failing ID with a
  one-line rationale

The job fails when a test fails that is **not** in the baseline (a regression),
or when a test **errors** (it could not execute, so its result is meaningless).
A known failure is still reported as a failure; it simply does not break the
build for behaviour that is already known and recorded.

When one of these is fixed, its test starts passing and the runner prints a
note asking for the baseline entry to be removed. After that, any regression
fails CI.

## Test environment

The workflow starts the server directly with `node index.js` on a hosted
runner, using a scratch config and metadata directory, and bootstraps it
through `/init`.

**It does not build the client.** The tests exercise server API routes, and
those routes work without `client/dist` present, so the Nuxt build is skipped
entirely. The whole job is dependency install plus server start.

`RATE_LIMIT_AUTH_MAX` and `RATE_LIMIT_AUTH_WINDOW` are set on the test instance.
These are configuration variables the application already supports. The test
**lowers the rate limiter's thresholds, it does not change its logic**: the code
path exercised is the same one used in production, just with a smaller window so
the test finishes in seconds instead of exhausting 40 attempts over ten minutes.

The script needs `ffmpeg` to generate a two-second silent MP3 as library
fixture. The server installs its own `ffmpeg` into the application root at first
start, and the script uses that copy automatically, so no extra packages are
required on the runner.

---

## ST-01 Login rate limiting and client-supplied address headers

- **WSTG:** WSTG-ATHN-03, Testing for Weak Lock Out Mechanism
- **Severity:** High
- **Status on 2.36.0:** Fails

Sends 12 failed logins with a fixed `X-Forwarded-For` as a control, then 12 more
with the header changing on every request, and asserts that rate limiting still
takes effect in the second phase.

The control matters: if the limiter were disabled or misconfigured, the second
phase would return no `429` and would look like a bypass. If the control
produces no `429`, the test reports `error` rather than `fail`, because its
result would otherwise be meaningless.

`server/utils/rateLimiterFactory.js` builds an `express-rate-limit` handler
whose `keyGenerator` calls `requestIp.getClientIp(req)`, which reads
client-supplied forwarding headers before falling back to the socket address.
The limiter is attached to `POST /login` and `POST /auth/refresh`.

**Observed:** control 7 of 12 rate limited, second phase 0 of 12. Each spoofed
address gets its own counter.

Credential stuffing and password spraying are the realistic attack against a
self-hosted server reachable on a network, and this limiter is the control that
makes them expensive.

---

## ST-02 Access token validity after logout

- **WSTG:** WSTG-SESS-06, Testing for Logout Functionality
- **Severity:** High
- **Status on 2.36.0:** Fails

Logs in, confirms the access token works, calls `POST /logout` with both the
bearer token and the refresh token, then reuses the same access token against
`GET /api/me` and asserts rejection.

`POST /logout` in `server/Auth.js` clears the `refresh_token` cookie and calls
`invalidateRefreshToken`, then `req.logout()`. Nothing revokes the
already-issued JWT access token, which stays verifiable until it expires.

**Observed:** `GET /api/me` returns `200` after a successful logout.

Logout is what a user reaches for after using a shared or untrusted device, and
what an administrator does when they think a token has leaked. If it does not
end access for a token that has already been copied, it offers assurance it does
not deliver.

---

## ST-03 Refresh tokens are not accepted as access tokens

- **WSTG:** WSTG-SESS-06, Testing for Logout Functionality
- **Severity:** Medium
- **Status on 2.36.0:** **Passes**

Logs in, then presents the refresh token in the `Authorization: Bearer` header
against `GET /api/me`, asserting rejection.

**Observed:** returns `401`. Token types are correctly separated on 2.36.0.

This test is included precisely because it passes. Token type confusion is easy
to reintroduce when refresh handling is refactored, and this locks in the
current, correct behaviour so a regression is caught immediately.

---

## ST-04 Content type of an uploaded non-media library file

- **WSTG:** WSTG-BUSL-09 (Testing Upload of Malicious Files), WSTG-INPV-02 (Testing for Stored Cross Site Scripting)
- **Severity:** High
- **Status on 2.36.0:** Fails

As a user whose only permission is `upload`, and who can reach exactly one
library, uploads a `.html` file, triggers a scan so it becomes a library file,
then fetches it and inspects the response headers. The test passes if the
content type is not `text/html` **or** if `Content-Disposition: attachment` is
set.

`MiscController.handleUpload` applies no extension or content type restriction.
`GET /api/items/:id/file/:ino` then serves the file with a content type derived
from it.

**Observed:** served as `Content-Type: text/html; charset=UTF-8` with no
attachment disposition, so script in the file runs in the application's own
origin, as any user who opens it.

The assertion accepts either defence deliberately, because the sibling route
`/api/items/:id/file/:ino/download` **already** sets an attachment disposition.
The safe behaviour exists in the codebase; it is simply not applied on the
inline route.

---

## ST-05 Library authorization on the media progress endpoints

- **WSTG:** WSTG-ATHZ-02, Testing for Bypassing Authorization Schema
- **Severity:** Medium
- **Status on 2.36.0:** Fails

Creates two libraries and a user with access to only the first. Confirms as a
control that `GET /api/items/<item in the second library>` is refused for that
user, then writes media progress for the same item and reads it back.

The control proves the item really is outside the user's authorization scope, so
a `200` from the progress endpoint is an inconsistency inside the application
rather than a mistake in the fixture.

Item routes in `server/routers/ApiRouter.js` are bound through
`LibraryItemController.middleware`, which enforces library access. The
`/api/me/progress/*` routes bind straight to `MeController` methods with no
equivalent check.

**Observed:** direct item read returns `403`; `PATCH /api/me/progress/:id`
returns `200`, and the value reads back with the library item id intact.

On a shared server, library separation is what keeps one user's collection
private from another. This lets a user confirm which item ids exist and attach
state to them regardless of that separation.

---

## ST-06 Authentication on the cover art route

- **WSTG:** WSTG-ATHZ-04, Testing for Insecure Direct Object References
- **Severity:** Medium
- **Status on 2.36.0:** Fails

Uploads a cover to an item in the restricted library as an administrator, then
requests that cover with no credentials at all, asserting `401` or `403`.

`this.router.get('/items/:id/cover', LibraryItemController.getCover)` is
registered without `LibraryItemController.middleware`, unlike the `POST`,
`PATCH` and `DELETE` handlers on the same path, which all carry it.

**Observed:** returns `200` with image data to an anonymous client.

Cover art carries title and author information, so anonymous read access
discloses the contents of private libraries to anyone who can reach the server
and obtain or guess an item id. The asymmetry with the other verbs on the same
route suggests an oversight rather than a deliberate exemption, which is exactly
the kind of thing worth a permanent regression test.

---

## Running the tests locally

```bash
# in one shell, from a clean checkout
npm ci --only=production
CONFIG_PATH=$PWD/sectest-config \
METADATA_PATH=$PWD/sectest-metadata \
RATE_LIMIT_AUTH_MAX=5 RATE_LIMIT_AUTH_WINDOW=60000 \
  node index.js

# in another
./scripts/security-tests.sh http://127.0.0.1:3333
```

The target must be a fresh, uninitialised instance the script can bootstrap
through `/init`; it refuses to run against an already-initialised server. The
script also has to run on a host sharing a filesystem with the server, because
it creates library folders the server then scans.
