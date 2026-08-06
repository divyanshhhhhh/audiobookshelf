#!/usr/bin/env bash
#
# Targeted security regression tests for Audiobookshelf.
#
# These tests exist because Semgrep, Trivy and a ZAP baseline scan are generic.
# They find classes of problem, not this application's specific authorization
# and session handling defects. Every test here traces to a finding the group
# raised in its own vulnerability report, and asserts the SECURE behaviour.
#
# Several of those vulnerabilities are real and unpatched upstream, so the
# corresponding tests fail today. That is deliberate and is NOT masked:
#
#   - every result is written to security-tests-results.json
#   - every result is printed here and summarised in the job step summary
#   - counts feed the notification issue like every other scanner
#
# security-tests-baseline.json records which IDs are known to fail and why.
# The job fails on a REGRESSION (a test that was passing and now fails) or on
# an ERROR (the test could not execute, meaning this harness is broken). This
# is the opposite of the `|| true` masking removed from this pipeline earlier:
# nothing disappears, a known failure is still reported as a failure, it simply
# does not re-break the build every run for a bug we have already reported.
#
# Usage:  scripts/security-tests.sh [base_url]
#
# Requires the target to be a FRESH, UNINITIALISED instance that this script
# owns and can bootstrap. Never point it at the hardened deployment or at the
# lab evidence containers.

set -uo pipefail

BASE_URL="${1:-http://localhost:18081}"
CONTAINER="${SECTEST_CONTAINER:-abs-sectest}"
RESULTS_FILE="${SECTEST_RESULTS:-security-tests-results.json}"
BASELINE_FILE="${SECTEST_BASELINE:-security-tests-baseline.json}"
WORK_DIR="$(mktemp -d)"
ENTRIES="$WORK_DIR/entries.jsonl"
: > "$ENTRIES"

ADMIN_USER="sectestadmin"
ADMIN_PASS="SecTestPass123!"
LOW_USER="lowpriv"
LOW_PASS="LowPrivPass123!"

# Bootstrap logins use their own X-Forwarded-For values so they occupy separate
# rate-limit buckets from ST-01, which deliberately exhausts one.
BOOTSTRAP_IP_ADMIN="10.255.0.1"
BOOTSTRAP_IP_LOW="10.255.0.2"

cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

log()  { echo "[security-tests] $*"; }
fatal() { echo "::error::[security-tests] $*"; exit 1; }

# record <id> <finding> <title> <wstg> <severity> <status> <evidence>
record() {
  jq -n --arg id "$1" --arg finding "$2" --arg title "$3" --arg wstg "$4" \
        --arg severity "$5" --arg status "$6" --arg evidence "$7" \
    '{id:$id, finding:$finding, title:$title, wstg:$wstg, severity:$severity, status:$status, evidence:$evidence}' \
    >> "$ENTRIES"
  printf '  %-6s %-6s %s\n           %s\n' "$1" "$6" "$3" "$7"
}

# status_of <method> <url> [curl args...] -> prints HTTP status, body in $WORK_DIR/body
status_of() {
  local method="$1" url="$2"; shift 2
  curl -s -X "$method" -o "$WORK_DIR/body" -D "$WORK_DIR/hdr" \
       -w '%{http_code}' --max-time 30 "$@" "$url"
}

wait_healthy() {
  local i
  for i in $(seq 1 60); do
    if curl -sf --max-time 5 "$BASE_URL/healthcheck" > /dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
log "target: $BASE_URL (container: $CONTAINER)"
wait_healthy || fatal "target never became healthy"

IS_INIT=$(curl -s --max-time 10 "$BASE_URL/status" | jq -r '.isInit // false')
if [ "$IS_INIT" != "true" ]; then
  CODE=$(status_of POST "$BASE_URL/init" -H 'Content-Type: application/json' \
    -d "{\"newRoot\":{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}}")
  [ "$CODE" = "200" ] || fatal "server init failed (HTTP $CODE)"
  sleep 3
fi

login() { # login <user> <pass> <xff> -> writes $WORK_DIR/login.json
  status_of POST "$BASE_URL/login" \
    -H 'Content-Type: application/json' -H 'x-return-tokens: true' \
    -H "X-Forwarded-For: $3" \
    -d "{\"username\":\"$1\",\"password\":\"$2\"}"
  cp "$WORK_DIR/body" "$WORK_DIR/login.json"
}

CODE=$(login "$ADMIN_USER" "$ADMIN_PASS" "$BOOTSTRAP_IP_ADMIN")
[ "$CODE" = "200" ] || fatal "admin login failed (HTTP $CODE)"
ADMIN_TOKEN=$(jq -r '.user.accessToken' "$WORK_DIR/login.json")
[ -n "$ADMIN_TOKEN" ] && [ "$ADMIN_TOKEN" != "null" ] || fatal "no admin access token in login response"
AUTH_ADMIN=(-H "Authorization: Bearer $ADMIN_TOKEN")

# Library folders must exist inside the container before a library can use them,
# and the sample audio file is produced by the ffmpeg the image already ships,
# so this harness adds no dependency to the runner.
docker exec "$CONTAINER" sh -c 'mkdir -p /audiobooks/libA /audiobooks/libB' \
  || fatal "could not create library folders in $CONTAINER"
docker exec "$CONTAINER" sh -c \
  'ffmpeg -loglevel error -f lavfi -i anullsrc=r=44100:cl=mono -t 2 -q:a 9 -y /tmp/track1.mp3' \
  || fatal "could not generate sample audio in $CONTAINER"
docker cp "$CONTAINER:/tmp/track1.mp3" "$WORK_DIR/track1.mp3" > /dev/null 2>&1 \
  || fatal "could not copy sample audio out of $CONTAINER"

create_library() { # create_library <name> <path> -> prints id
  status_of POST "$BASE_URL/api/libraries" "${AUTH_ADMIN[@]}" \
    -H 'Content-Type: application/json' \
    -d "{\"name\":\"$1\",\"folders\":[{\"fullPath\":\"$2\"}],\"mediaType\":\"book\"}" > /dev/null
  jq -r '.id' "$WORK_DIR/body"
}

LIB_A=$(create_library "SecTestLibA" "/audiobooks/libA")
LIB_B=$(create_library "SecTestLibB" "/audiobooks/libB")
[ -n "$LIB_A" ] && [ "$LIB_A" != "null" ] || fatal "could not create library A"
[ -n "$LIB_B" ] && [ "$LIB_B" != "null" ] || fatal "could not create library B"

status_of GET "$BASE_URL/api/libraries/$LIB_A" "${AUTH_ADMIN[@]}" > /dev/null
FOLDER_A=$(jq -r '.folders[0].id' "$WORK_DIR/body")
[ -n "$FOLDER_A" ] && [ "$FOLDER_A" != "null" ] || fatal "could not resolve library A folder id"

# Low-privilege user: access to library A only, upload allowed, nothing else.
# isActive must be set explicitly; it defaults to false and the account cannot
# log in without it.
CODE=$(status_of POST "$BASE_URL/api/users" "${AUTH_ADMIN[@]}" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$LOW_USER\",\"password\":\"$LOW_PASS\",\"type\":\"user\",\"isActive\":true,
       \"permissions\":{\"download\":true,\"update\":false,\"delete\":false,\"upload\":true,
                        \"accessAllLibraries\":false,\"accessAllTags\":true,\"accessExplicitContent\":true},
       \"librariesAccessible\":[\"$LIB_A\"]}")
[ "$CODE" = "200" ] || fatal "could not create low-privilege user (HTTP $CODE)"
LOW_ID=$(jq -r '.user.id' "$WORK_DIR/body")
status_of PATCH "$BASE_URL/api/users/$LOW_ID" "${AUTH_ADMIN[@]}" \
  -H 'Content-Type: application/json' -d '{"isActive":true}' > /dev/null

CODE=$(login "$LOW_USER" "$LOW_PASS" "$BOOTSTRAP_IP_LOW")
[ "$CODE" = "200" ] || fatal "low-privilege login failed (HTTP $CODE)"
LOW_TOKEN=$(jq -r '.user.accessToken' "$WORK_DIR/login.json")
AUTH_LOW=(-H "Authorization: Bearer $LOW_TOKEN")

# A real library item in library B, which the low-privilege user cannot see.
status_of POST "$BASE_URL/api/upload" "${AUTH_ADMIN[@]}" \
  -F "library=$LIB_B" -F "folder=$(jq -r '.folders[0].id' <(curl -s "${AUTH_ADMIN[@]}" "$BASE_URL/api/libraries/$LIB_B"))" \
  -F "title=PrivateBook" -F "author=AuthorX" -F "files=@$WORK_DIR/track1.mp3" > /dev/null
status_of POST "$BASE_URL/api/libraries/$LIB_B/scan" "${AUTH_ADMIN[@]}" > /dev/null
sleep 15
status_of GET "$BASE_URL/api/libraries/$LIB_B/items" "${AUTH_ADMIN[@]}" > /dev/null
ITEM_B=$(jq -r '.results[0].id // empty' "$WORK_DIR/body")
[ -n "$ITEM_B" ] || fatal "library B item was not created, fixtures unusable"

# Give that item a cover so ST-06 can prove content is actually served.
docker exec "$CONTAINER" sh -c \
  'ffmpeg -loglevel error -f lavfi -i color=c=red:s=32x32 -frames:v 1 -y /tmp/cover.png' > /dev/null 2>&1
docker cp "$CONTAINER:/tmp/cover.png" "$WORK_DIR/cover.png" > /dev/null 2>&1
status_of POST "$BASE_URL/api/items/$ITEM_B/cover" "${AUTH_ADMIN[@]}" \
  -F "cover=@$WORK_DIR/cover.png" > /dev/null

log "fixtures ready: libA=$LIB_A libB=$LIB_B itemB=$ITEM_B"
echo
log "running tests"

# ---------------------------------------------------------------------------
# ST-01  Authentication rate limiting is keyed on a spoofable header (V-05)
# ---------------------------------------------------------------------------
# The limiter keys off requestIp.getClientIp(), which trusts X-Forwarded-For.
# The control phase proves the limiter is active and correctly configured; if
# the control never yields 429 the test reports `error`, because a silent
# limiter would make the attack phase look falsely secure.
RL_CONTROL=0
for i in $(seq 1 12); do
  C=$(status_of POST "$BASE_URL/login" -H 'Content-Type: application/json' \
        -H 'X-Forwarded-For: 10.9.9.9' \
        -d "{\"username\":\"$ADMIN_USER\",\"password\":\"wrong-password\"}")
  [ "$C" = "429" ] && RL_CONTROL=$((RL_CONTROL + 1))
done

RL_ATTACK=0
for i in $(seq 1 12); do
  C=$(status_of POST "$BASE_URL/login" -H 'Content-Type: application/json' \
        -H "X-Forwarded-For: 10.8.$i.$i" \
        -d "{\"username\":\"$ADMIN_USER\",\"password\":\"wrong-password\"}")
  [ "$C" = "429" ] && RL_ATTACK=$((RL_ATTACK + 1))
done

if [ "$RL_CONTROL" -eq 0 ]; then
  record "ST-01" "V-05" "Auth rate limiting resists client-IP header spoofing" \
    "WSTG-ATHN-03" "high" "error" \
    "Control phase never returned 429 after 12 failed logins from one address; the rate limiter is disabled or misconfigured, so the attack phase cannot be interpreted."
elif [ "$RL_ATTACK" -gt 0 ]; then
  record "ST-01" "V-05" "Auth rate limiting resists client-IP header spoofing" \
    "WSTG-ATHN-03" "high" "pass" \
    "Rotating X-Forwarded-For still triggered $RL_ATTACK/12 rate-limited responses; the limiter does not trust the header."
else
  record "ST-01" "V-05" "Auth rate limiting resists client-IP header spoofing" \
    "WSTG-ATHN-03" "high" "fail" \
    "Control: $RL_CONTROL/12 requests were rate limited from a fixed address. Attack: 0/12 were limited when X-Forwarded-For rotated. Brute-force protection is bypassed by setting a header the client controls."
fi

# ---------------------------------------------------------------------------
# ST-02  Access tokens survive logout (V-04)
# ---------------------------------------------------------------------------
CODE=$(login "$ADMIN_USER" "$ADMIN_PASS" "$BOOTSTRAP_IP_ADMIN")
if [ "$CODE" != "200" ]; then
  record "ST-02" "V-04" "Access token is rejected after logout" "WSTG-SESS-06" "high" "error" \
    "Could not log in to obtain a session (HTTP $CODE)."
else
  S_TOKEN=$(jq -r '.user.accessToken' "$WORK_DIR/login.json")
  S_REFRESH=$(jq -r '.user.refreshToken' "$WORK_DIR/login.json")
  PRE=$(status_of GET "$BASE_URL/api/me" -H "Authorization: Bearer $S_TOKEN")
  if [ "$PRE" != "200" ]; then
    record "ST-02" "V-04" "Access token is rejected after logout" "WSTG-SESS-06" "high" "error" \
      "Token was not usable before logout (HTTP $PRE), so the test cannot measure revocation."
  else
    status_of POST "$BASE_URL/logout" -H "Authorization: Bearer $S_TOKEN" \
      -H "x-refresh-token: $S_REFRESH" > /dev/null
    POST_LOGOUT=$(status_of GET "$BASE_URL/api/me" -H "Authorization: Bearer $S_TOKEN")
    if [ "$POST_LOGOUT" = "401" ] || [ "$POST_LOGOUT" = "403" ]; then
      record "ST-02" "V-04" "Access token is rejected after logout" "WSTG-SESS-06" "high" "pass" \
        "GET /api/me returned $POST_LOGOUT after logout; the access token was revoked."
    else
      record "ST-02" "V-04" "Access token is rejected after logout" "WSTG-SESS-06" "high" "fail" \
        "GET /api/me returned $POST_LOGOUT after a successful logout. Logout clears the refresh cookie but the bearer access token stays valid until it expires, so a stolen token is unaffected by signing out."
    fi
  fi
fi

# ---------------------------------------------------------------------------
# ST-03  Refresh tokens must not authenticate as access tokens (V-04)
# ---------------------------------------------------------------------------
CODE=$(login "$ADMIN_USER" "$ADMIN_PASS" "$BOOTSTRAP_IP_ADMIN")
if [ "$CODE" != "200" ]; then
  record "ST-03" "V-04" "Refresh token is not accepted as a bearer access token" \
    "WSTG-SESS-06" "medium" "error" "Could not log in to obtain a refresh token (HTTP $CODE)."
else
  R_TOKEN=$(jq -r '.user.refreshToken' "$WORK_DIR/login.json")
  RCODE=$(status_of GET "$BASE_URL/api/me" -H "Authorization: Bearer $R_TOKEN")
  if [ "$RCODE" = "401" ] || [ "$RCODE" = "403" ]; then
    record "ST-03" "V-04" "Refresh token is not accepted as a bearer access token" \
      "WSTG-SESS-06" "medium" "pass" \
      "GET /api/me with the refresh token returned $RCODE; token types are correctly separated."
  else
    record "ST-03" "V-04" "Refresh token is not accepted as a bearer access token" \
      "WSTG-SESS-06" "medium" "fail" \
      "GET /api/me with a refresh token in the Authorization header returned $RCODE, so a long-lived refresh token grants API access directly."
  fi
fi

# ---------------------------------------------------------------------------
# ST-04  Uploaded HTML served inline in the application origin (V-01)
# ---------------------------------------------------------------------------
# Files must be uploaded one request at a time; see ST-07 for why.
printf '<html><body><script>alert(document.domain)</script>stored-xss-probe</body></html>' \
  > "$WORK_DIR/evil.html"
status_of POST "$BASE_URL/api/upload" "${AUTH_LOW[@]}" \
  -F "library=$LIB_A" -F "folder=$FOLDER_A" -F "title=UploadProbe" -F "author=AuthorZ" \
  -F "files=@$WORK_DIR/track1.mp3" > /dev/null
UP=$(status_of POST "$BASE_URL/api/upload" "${AUTH_LOW[@]}" \
  -F "library=$LIB_A" -F "folder=$FOLDER_A" -F "title=UploadProbe" -F "author=AuthorZ" \
  -F "files=@$WORK_DIR/evil.html")
status_of POST "$BASE_URL/api/libraries/$LIB_A/scan" "${AUTH_ADMIN[@]}" > /dev/null
sleep 15
status_of GET "$BASE_URL/api/libraries/$LIB_A/items" "${AUTH_ADMIN[@]}" > /dev/null
ITEM_A=$(jq -r '.results[0].id // empty' "$WORK_DIR/body")

if [ "$UP" != "200" ]; then
  record "ST-04" "V-01" "Uploaded HTML is not served inline as same-origin text/html" \
    "WSTG-BUSL-09, WSTG-INPV-02" "high" "pass" \
    "Upload of a .html file by a user holding only the upload permission was rejected (HTTP $UP)."
elif [ -z "$ITEM_A" ]; then
  record "ST-04" "V-01" "Uploaded HTML is not served inline as same-origin text/html" \
    "WSTG-BUSL-09, WSTG-INPV-02" "high" "error" \
    "The uploaded file was accepted but no library item was produced, so the serving behaviour could not be measured."
else
  status_of GET "$BASE_URL/api/items/$ITEM_A" "${AUTH_ADMIN[@]}" > /dev/null
  HTML_INO=$(jq -r '.libraryFiles[]? | select(.metadata.ext==".html") | .ino' "$WORK_DIR/body" | head -1)
  if [ -z "$HTML_INO" ]; then
    record "ST-04" "V-01" "Uploaded HTML is not served inline as same-origin text/html" \
      "WSTG-BUSL-09, WSTG-INPV-02" "high" "pass" \
      "The .html file was accepted on upload but is not exposed as a library file, so it cannot be fetched."
  else
    FCODE=$(status_of GET "$BASE_URL/api/items/$ITEM_A/file/$HTML_INO" "${AUTH_LOW[@]}")
    CTYPE=$(grep -i '^content-type:' "$WORK_DIR/hdr" | tr -d '\r' | head -1 | cut -d' ' -f2-)
    CDISP=$(grep -ic '^content-disposition: *attachment' "$WORK_DIR/hdr")
    if [ "$CDISP" -gt 0 ] || ! echo "$CTYPE" | grep -qi 'text/html'; then
      record "ST-04" "V-01" "Uploaded HTML is not served inline as same-origin text/html" \
        "WSTG-BUSL-09, WSTG-INPV-02" "high" "pass" \
        "File served with Content-Type '$CTYPE' and attachment disposition present=$CDISP; it cannot execute in the application origin."
    else
      record "ST-04" "V-01" "Uploaded HTML is not served inline as same-origin text/html" \
        "WSTG-BUSL-09, WSTG-INPV-02" "high" "fail" \
        "A user holding only the upload permission stored an .html file which GET /api/items/$ITEM_A/file/$HTML_INO returns as HTTP $FCODE with Content-Type '$CTYPE' and no attachment disposition. Script in that file executes in the application's own origin, giving stored XSS against any user who opens it."
    fi
  fi
fi




fdgbadsfhbsgjhw5ysrjn
# ---------------------------------------------------------------------------
# ST-05  Media progress bypasses library authorization (V-09)
# ---------------------------------------------------------------------------
CTRL_ITEM=$(status_of GET "$BASE_URL/api/items/$ITEM_B" "${AUTH_LOW[@]}")
PCODE=$(status_of PATCH "$BASE_URL/api/me/progress/$ITEM_B" "${AUTH_LOW[@]}" \
  -H 'Content-Type: application/json' -d '{"progress":0.5,"currentTime":30}')
GCODE=$(status_of GET "$BASE_URL/api/me/progress/$ITEM_B" "${AUTH_LOW[@]}")
STORED=$(jq -r '.libraryItemId // empty' "$WORK_DIR/body" 2>/dev/null)

if [ "$CTRL_ITEM" = "200" ]; then
  record "ST-05" "V-09" "Media progress respects library authorization" "WSTG-ATHZ-02" "medium" "error" \
    "The low-privilege user could read the library B item directly (HTTP $CTRL_ITEM), so the fixture does not represent an inaccessible library."
elif [ "$PCODE" = "403" ] || [ "$PCODE" = "404" ]; then
  record "ST-05" "V-09" "Media progress respects library authorization" "WSTG-ATHZ-02" "medium" "pass" \
    "Direct item access returned $CTRL_ITEM and the media-progress write returned $PCODE; the endpoint enforces the same library authorization."
else
  record "ST-05" "V-09" "Media progress respects library authorization" "WSTG-ATHZ-02" "medium" "fail" \
    "GET /api/items/$ITEM_B returns $CTRL_ITEM for this user, but PATCH /api/me/progress/$ITEM_B returned $PCODE and the value reads back with GET returning $GCODE (libraryItemId='$STORED'). The media-progress endpoints do not apply the library access check the rest of the item API applies, so a user can confirm the existence of, and store state against, items in libraries they cannot see."
fi

# ---------------------------------------------------------------------------
# ST-06  Cover art served without authentication (V-14)
# ---------------------------------------------------------------------------
ANON=$(status_of GET "$BASE_URL/api/items/$ITEM_B/cover")
ANON_TYPE=$(grep -i '^content-type:' "$WORK_DIR/hdr" | tr -d '\r' | head -1 | cut -d' ' -f2-)
ANON_BYTES=$(wc -c < "$WORK_DIR/body" | tr -d ' ')
if [ "$ANON" = "401" ] || [ "$ANON" = "403" ]; then
  record "ST-06" "V-14" "Cover art requires authentication" "WSTG-ATHZ-04" "medium" "pass" \
    "Unauthenticated GET /api/items/$ITEM_B/cover returned $ANON."
else
  record "ST-06" "V-14" "Cover art requires authentication" "WSTG-ATHZ-04" "medium" "fail" \
    "Unauthenticated GET /api/items/$ITEM_B/cover returned HTTP $ANON with Content-Type '$ANON_TYPE' and $ANON_BYTES bytes of image data. The route carries no authentication middleware, so cover art for any item in any library is readable by anyone who can reach the server, without a session."
fi

# ---------------------------------------------------------------------------
# ST-07  Unhandled rejection in the upload handler terminates the server
# ---------------------------------------------------------------------------
# Discovered while building ST-04, not present in the group's original report.
# Posting two files under the same form field makes Object.values(req.files)
# yield a nested array, so file.name is undefined, sanitizeFilename returns
# false, and Path.join throws inside an async handler with no catch. The
# rejection is fatal and the process exits.
#
# THIS TEST MUST REMAIN LAST. When it fails it does so by killing the target,
# and anything after it would report `error` for the wrong reason.
UP2=$(status_of POST "$BASE_URL/api/upload" "${AUTH_LOW[@]}" \
  -F "library=$LIB_A" -F "folder=$FOLDER_A" -F "title=CrashProbe" -F "author=AuthorZ" \
  -F "files=@$WORK_DIR/track1.mp3" -F "files=@$WORK_DIR/evil.html")
sleep 5
if curl -sf --max-time 10 "$BASE_URL/healthcheck" > /dev/null 2>&1; then
  record "ST-07" "new" "Upload handler survives a malformed multipart request" \
    "WSTG-BUSL-09, WSTG-ERRH-02" "high" "pass" \
    "Upload returned HTTP $UP2 and the server remained healthy."
else
  RUNNING=$(docker inspect "$CONTAINER" --format '{{.State.Running}}' 2>/dev/null || echo "unknown")
  record "ST-07" "new" "Upload handler survives a malformed multipart request" \
    "WSTG-BUSL-09, WSTG-ERRH-02" "high" "fail" \
    "A user holding only the upload permission sent two files under one form field (HTTP $UP2). The server stopped responding to /healthcheck and the container Running state is now '$RUNNING'. MiscController.handleUpload passes a non-string to Path.join inside an unawaited promise, producing a fatal unhandled rejection. Any authenticated uploader can terminate the service with one request."
fi

# ---------------------------------------------------------------------------
# Results, baseline comparison, exit status
# ---------------------------------------------------------------------------
echo
jq -s --arg target "$BASE_URL" --arg generated "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{generated:$generated, target:$target, results:., summary:{
      total: length,
      pass:  [.[] | select(.status=="pass")]  | length,
      fail:  [.[] | select(.status=="fail")]  | length,
      error: [.[] | select(.status=="error")] | length
   }}' "$ENTRIES" > "$RESULTS_FILE"

PASS=$(jq -r '.summary.pass'  "$RESULTS_FILE")
FAIL=$(jq -r '.summary.fail'  "$RESULTS_FILE")
ERROR=$(jq -r '.summary.error' "$RESULTS_FILE")
log "results: $PASS passed, $FAIL failed, $ERROR errored -> $RESULTS_FILE"

if [ ! -f "$BASELINE_FILE" ]; then
  fatal "baseline file $BASELINE_FILE is missing; refusing to guess which failures are expected"
fi

# `.id` must be bound before piping into the baseline object, otherwise `.`
# inside has() refers to known_failing rather than the result entry and the
# comparison silently matches nothing, which would hide every regression.
REGRESSIONS=$(jq -r --slurpfile b "$BASELINE_FILE" \
  '[.results[] | select(.status=="fail") | .id as $id | select(($b[0].known_failing | has($id)) | not) | $id] | join(" ")' \
  "$RESULTS_FILE")
ERRORED=$(jq -r '[.results[] | select(.status=="error") | .id] | join(" ")' "$RESULTS_FILE")
FIXED=$(jq -r --slurpfile b "$BASELINE_FILE" \
  '[.results[] | select(.status=="pass") | .id as $id | select($b[0].known_failing | has($id)) | $id] | join(" ")' \
  "$RESULTS_FILE")

if [ -n "$FIXED" ]; then
  log "NOTE: baseline lists these as known-failing but they now pass: $FIXED"
  log "      remove them from $BASELINE_FILE so a future regression is caught."
fi

# ---------------------------------------------------------------------------
# Exit policy
# ---------------------------------------------------------------------------
# Two modes, because "did anything fail" and "did anything get worse" are
# different questions and only the second one can gate a merge here.
#
# Default (SECTEST_STRICT unset or 0): fail only on a regression, meaning a
# failing test absent from the baseline, or on an error, meaning a test could
# not execute so its result is meaningless.
#
# Strict (SECTEST_STRICT=1): fail if any test is failing or errored at all.
#
# Strict is deliberately NOT the default. Six of the seven tests currently fail
# against unpatched upstream code. A strict default would therefore mark every
# commit red, block every merge, and, because the deploy job depends on this
# one, stop the deployment from ever running. That would destroy the very
# evidence the gate exists to protect: a pipeline that can never go green tells
# you nothing about whether a change made things worse, and teams quickly learn
# to bypass a check that is permanently red.
#
# Strict mode is useful for a release candidate, or on a fork where the
# underlying findings have been fixed and the expected state is genuinely zero.
STRICT="${SECTEST_STRICT:-0}"

FAILING_IDS=$(jq -r '[.results[] | select(.status=="fail" or .status=="error") | .id] | join(" ")' "$RESULTS_FILE")

STATUS=0
if [ "$STRICT" = "1" ]; then
  log "mode: STRICT (SECTEST_STRICT=1) - any failing or errored test fails this run"
  if [ -n "$FAILING_IDS" ]; then
    echo "::error::Strict mode: $FAIL failing and $ERROR errored test(s): $FAILING_IDS"
    log "strict-mode failures: $FAILING_IDS"
    STATUS=1
  else
    log "strict mode satisfied: no failing or errored tests"
  fi
else
  log "mode: BASELINE (default) - only regressions and errors fail this run"
  if [ -n "$ERRORED" ]; then
    echo "::error::Security tests could not execute: $ERRORED. The harness or its fixtures are broken."
    STATUS=1
  fi
  if [ -n "$REGRESSIONS" ]; then
    echo "::error::Security regression detected in: $REGRESSIONS (failing, and not listed in the baseline)."
    STATUS=1
  fi
  if [ "$STATUS" -eq 0 ] && [ "$FAIL" -gt 0 ]; then
    log "$FAIL known-failing test(s) reported. These are unpatched findings recorded in $BASELINE_FILE, not regressions."
  fi
fi
exit "$STATUS"
