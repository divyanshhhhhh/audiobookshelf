#!/usr/bin/env bash
#
# Application-specific security regression tests for Audiobookshelf.
#
# These complement, rather than duplicate, the static analysis already in CI.
# CodeQL and Semgrep recognise categories of defect that look the same in every
# application. They cannot know what this application's authorization rules are
# supposed to be, so they do not report that logging out leaves a bearer token
# valid, that the media progress endpoints skip the library access check, or
# that cover art is readable without a session. Each test below asserts one
# specific expected behaviour and fails loudly if it changes.
#
# Some of the tested behaviours are not yet the secure ones, so those tests
# fail today. That is recorded, not hidden:
#
#   - every result is written to security-tests-results.json
#   - every result is printed here and summarised in the CI job summary
#   - security-tests-baseline.json lists the currently-failing IDs with a
#     one-line rationale for each
#
# The suite exits non-zero on a REGRESSION (a failure not listed in the
# baseline) or on an ERROR (a test that could not execute, meaning the harness
# itself is broken). A known failure is still reported as a failure; it simply
# does not break the build for behaviour that is already known.
#
# When a behaviour is fixed, its test starts passing and the runner says so,
# prompting removal of the baseline entry, after which any regression fails CI.
#
# Usage:
#   scripts/security-tests.sh [base_url]
#
# Requirements:
#   - the target must be a fresh, uninitialised instance this script can
#     bootstrap through /init
#   - this script must run on a host that shares a filesystem with the server,
#     because it creates library folders the server then scans
#   - jq, curl, and ffmpeg. The server downloads its own ffmpeg into the
#     application root at first start, and that copy is used automatically if
#     no system ffmpeg is present.
#
# Environment:
#   SECTEST_MEDIA_ROOT  directory used for test libraries (default ./sectest-media)
#   SECTEST_RESULTS     results file  (default security-tests-results.json)
#   SECTEST_BASELINE    baseline file (default security-tests-baseline.json)

set -uo pipefail

BASE_URL="${1:-http://localhost:3333}"
MEDIA_ROOT="${SECTEST_MEDIA_ROOT:-$PWD/sectest-media}"
RESULTS_FILE="${SECTEST_RESULTS:-security-tests-results.json}"
BASELINE_FILE="${SECTEST_BASELINE:-security-tests-baseline.json}"
WORK_DIR="$(mktemp -d)"
ENTRIES="$WORK_DIR/entries.jsonl"
: > "$ENTRIES"

ADMIN_USER="sectestadmin"
ADMIN_PASS="SecTestPass123!"
LOW_USER="sectestlowpriv"
LOW_PASS="LowPrivPass123!"

# Bootstrap logins use their own X-Forwarded-For values so that they occupy
# rate limit buckets separate from ST-01, which deliberately exhausts one.
BOOTSTRAP_IP_ADMIN="10.255.0.1"
BOOTSTRAP_IP_LOW="10.255.0.2"

cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

log()   { echo "[security-tests] $*"; }
fatal() { echo "::error::[security-tests] $*"; exit 1; }

# record <id> <title> <wstg> <severity> <status> <evidence>
record() {
  jq -n --arg id "$1" --arg title "$2" --arg wstg "$3" \
        --arg severity "$4" --arg status "$5" --arg evidence "$6" \
    '{id:$id, title:$title, wstg:$wstg, severity:$severity, status:$status, evidence:$evidence}' \
    >> "$ENTRIES"
  printf '  %-6s %-6s %s\n           %s\n' "$1" "$5" "$2" "$6"
}

# status_of <method> <url> [curl args...] -> prints status; body in $WORK_DIR/body
status_of() {
  local method="$1" url="$2"; shift 2
  curl -s -X "$method" -o "$WORK_DIR/body" -D "$WORK_DIR/hdr" \
       -w '%{http_code}' --max-time 30 "$@" "$url"
}

# The server installs ffmpeg into the application root on first start, so a
# system ffmpeg is convenient but not required.
find_ffmpeg() {
  if [ -n "${FFMPEG_PATH:-}" ] && [ -x "${FFMPEG_PATH}" ]; then
    echo "$FFMPEG_PATH"; return 0
  fi
  if [ -x "./ffmpeg" ]; then
    echo "./ffmpeg"; return 0
  fi
  command -v ffmpeg 2>/dev/null && return 0
  return 1
}

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
log "target: $BASE_URL"
command -v jq > /dev/null || fatal "jq is required"

for i in $(seq 1 60); do
  curl -sf --max-time 5 "$BASE_URL/healthcheck" > /dev/null 2>&1 && break
  [ "$i" = "60" ] && fatal "target never became healthy"
  sleep 2
done

FFMPEG="$(find_ffmpeg)" || fatal "ffmpeg not found; start the server once so it installs its own, or install ffmpeg"
log "using ffmpeg: $FFMPEG"

IS_INIT=$(curl -s --max-time 10 "$BASE_URL/status" | jq -r '.isInit // false')
if [ "$IS_INIT" != "true" ]; then
  CODE=$(status_of POST "$BASE_URL/init" -H 'Content-Type: application/json' \
    -d "{\"newRoot\":{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}}")
  [ "$CODE" = "200" ] || fatal "server init failed (HTTP $CODE)"
  sleep 3
else
  fatal "target is already initialised; these tests need a fresh instance they can bootstrap"
fi

login() { # login <user> <pass> <xff>
  status_of POST "$BASE_URL/login" \
    -H 'Content-Type: application/json' -H 'x-return-tokens: true' \
    -H "X-Forwarded-For: $3" \
    -d "{\"username\":\"$1\",\"password\":\"$2\"}"
  cp "$WORK_DIR/body" "$WORK_DIR/login.json"
}

CODE=$(login "$ADMIN_USER" "$ADMIN_PASS" "$BOOTSTRAP_IP_ADMIN")
[ "$CODE" = "200" ] || fatal "admin login failed (HTTP $CODE)"
ADMIN_TOKEN=$(jq -r '.user.accessToken' "$WORK_DIR/login.json")
[ -n "$ADMIN_TOKEN" ] && [ "$ADMIN_TOKEN" != "null" ] || fatal "no access token in login response"
AUTH_ADMIN=(-H "Authorization: Bearer $ADMIN_TOKEN")

# Two libraries: the low-privilege user is granted access to the first only.
mkdir -p "$MEDIA_ROOT/libA" "$MEDIA_ROOT/libB" || fatal "cannot create $MEDIA_ROOT"
"$FFMPEG" -loglevel error -f lavfi -i anullsrc=r=44100:cl=mono -t 2 -q:a 9 \
  -y "$WORK_DIR/track1.mp3" || fatal "could not generate sample audio"
"$FFMPEG" -loglevel error -f lavfi -i color=c=red:s=32x32 -frames:v 1 \
  -y "$WORK_DIR/cover.png" || fatal "could not generate sample cover"

create_library() { # create_library <name> <path>
  status_of POST "$BASE_URL/api/libraries" "${AUTH_ADMIN[@]}" \
    -H 'Content-Type: application/json' \
    -d "{\"name\":\"$1\",\"folders\":[{\"fullPath\":\"$2\"}],\"mediaType\":\"book\"}" > /dev/null
  jq -r '.id' "$WORK_DIR/body"
}

LIB_A=$(create_library "SecTestLibA" "$MEDIA_ROOT/libA")
LIB_B=$(create_library "SecTestLibB" "$MEDIA_ROOT/libB")
[ -n "$LIB_A" ] && [ "$LIB_A" != "null" ] || fatal "could not create library A"
[ -n "$LIB_B" ] && [ "$LIB_B" != "null" ] || fatal "could not create library B"

status_of GET "$BASE_URL/api/libraries/$LIB_A" "${AUTH_ADMIN[@]}" > /dev/null
FOLDER_A=$(jq -r '.folders[0].id' "$WORK_DIR/body")
status_of GET "$BASE_URL/api/libraries/$LIB_B" "${AUTH_ADMIN[@]}" > /dev/null
FOLDER_B=$(jq -r '.folders[0].id' "$WORK_DIR/body")
[ -n "$FOLDER_A" ] && [ "$FOLDER_A" != "null" ] || fatal "could not resolve library A folder id"

# isActive must be set explicitly; the account cannot log in without it.
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

# A real item in library B, which the low-privilege user cannot see.
status_of POST "$BASE_URL/api/upload" "${AUTH_ADMIN[@]}" \
  -F "library=$LIB_B" -F "folder=$FOLDER_B" \
  -F "title=PrivateBook" -F "author=AuthorX" -F "files=@$WORK_DIR/track1.mp3" > /dev/null
status_of POST "$BASE_URL/api/libraries/$LIB_B/scan" "${AUTH_ADMIN[@]}" > /dev/null
sleep 15
status_of GET "$BASE_URL/api/libraries/$LIB_B/items" "${AUTH_ADMIN[@]}" > /dev/null
ITEM_B=$(jq -r '.results[0].id // empty' "$WORK_DIR/body")
[ -n "$ITEM_B" ] || fatal "library B item was not created, fixtures unusable"

status_of POST "$BASE_URL/api/items/$ITEM_B/cover" "${AUTH_ADMIN[@]}" \
  -F "cover=@$WORK_DIR/cover.png" > /dev/null

log "fixtures ready"
echo
log "running tests"

# ---------------------------------------------------------------------------
# ST-01  Authentication rate limiting and client-supplied address headers
# ---------------------------------------------------------------------------
# The control phase proves the limiter is active and correctly configured. If
# the control never yields 429 the test reports `error`, because a silent
# limiter would make the second phase look falsely secure.
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
  record "ST-01" "Login rate limiting is not bypassed by a client-supplied address header" \
    "WSTG-ATHN-03" "high" "error" \
    "Control phase never returned 429 after 12 failed logins from one address; the rate limiter is disabled or misconfigured, so the second phase cannot be interpreted."
elif [ "$RL_ATTACK" -gt 0 ]; then
  record "ST-01" "Login rate limiting is not bypassed by a client-supplied address header" \
    "WSTG-ATHN-03" "high" "pass" \
    "Rotating X-Forwarded-For still produced $RL_ATTACK/12 rate limited responses."
else
  record "ST-01" "Login rate limiting is not bypassed by a client-supplied address header" \
    "WSTG-ATHN-03" "high" "fail" \
    "Control: $RL_CONTROL/12 requests were rate limited from a fixed address. Second phase: 0/12 were limited when X-Forwarded-For rotated per request. The limiter keys on requestIp.getClientIp(), which reads forwarding headers before the socket address, so a client that varies the header is never throttled."
fi

# ---------------------------------------------------------------------------
# ST-02  Access token validity after logout
# ---------------------------------------------------------------------------
CODE=$(login "$ADMIN_USER" "$ADMIN_PASS" "$BOOTSTRAP_IP_ADMIN")
if [ "$CODE" != "200" ]; then
  record "ST-02" "Access token is rejected after logout" "WSTG-SESS-06" "high" "error" \
    "Could not log in to obtain a session (HTTP $CODE)."
else
  S_TOKEN=$(jq -r '.user.accessToken' "$WORK_DIR/login.json")
  S_REFRESH=$(jq -r '.user.refreshToken' "$WORK_DIR/login.json")
  PRE=$(status_of GET "$BASE_URL/api/me" -H "Authorization: Bearer $S_TOKEN")
  if [ "$PRE" != "200" ]; then
    record "ST-02" "Access token is rejected after logout" "WSTG-SESS-06" "high" "error" \
      "Token was not usable before logout (HTTP $PRE), so revocation cannot be measured."
  else
    status_of POST "$BASE_URL/logout" -H "Authorization: Bearer $S_TOKEN" \
      -H "x-refresh-token: $S_REFRESH" > /dev/null
    AFTER=$(status_of GET "$BASE_URL/api/me" -H "Authorization: Bearer $S_TOKEN")
    if [ "$AFTER" = "401" ] || [ "$AFTER" = "403" ]; then
      record "ST-02" "Access token is rejected after logout" "WSTG-SESS-06" "high" "pass" \
        "GET /api/me returned $AFTER after logout."
    else
      record "ST-02" "Access token is rejected after logout" "WSTG-SESS-06" "high" "fail" \
        "GET /api/me returned $AFTER after a successful logout. Logout clears the refresh token cookie and invalidates the refresh token, but the already-issued bearer access token stays valid until it expires, so signing out does not end access for a token that has been copied."
    fi
  fi
fi

# ---------------------------------------------------------------------------
# ST-03  Refresh tokens must not be accepted as access tokens
# ---------------------------------------------------------------------------
CODE=$(login "$ADMIN_USER" "$ADMIN_PASS" "$BOOTSTRAP_IP_ADMIN")
if [ "$CODE" != "200" ]; then
  record "ST-03" "Refresh token is not accepted as a bearer access token" \
    "WSTG-SESS-06" "medium" "error" "Could not log in to obtain a refresh token (HTTP $CODE)."
else
  R_TOKEN=$(jq -r '.user.refreshToken' "$WORK_DIR/login.json")
  RCODE=$(status_of GET "$BASE_URL/api/me" -H "Authorization: Bearer $R_TOKEN")
  if [ "$RCODE" = "401" ] || [ "$RCODE" = "403" ]; then
    record "ST-03" "Refresh token is not accepted as a bearer access token" \
      "WSTG-SESS-06" "medium" "pass" \
      "GET /api/me with the refresh token returned $RCODE; token types are correctly separated."
  else
    record "ST-03" "Refresh token is not accepted as a bearer access token" \
      "WSTG-SESS-06" "medium" "fail" \
      "GET /api/me with a refresh token in the Authorization header returned $RCODE, so a long-lived refresh token grants API access directly."
  fi
fi

# ---------------------------------------------------------------------------
# ST-04  Content type of an uploaded non-media library file
# ---------------------------------------------------------------------------
printf '<html><body><script>/* stored xss probe */</script>probe</body></html>' \
  > "$WORK_DIR/probe.html"
status_of POST "$BASE_URL/api/upload" "${AUTH_LOW[@]}" \
  -F "library=$LIB_A" -F "folder=$FOLDER_A" -F "title=UploadProbe" -F "author=AuthorZ" \
  -F "files=@$WORK_DIR/track1.mp3" > /dev/null
UP=$(status_of POST "$BASE_URL/api/upload" "${AUTH_LOW[@]}" \
  -F "library=$LIB_A" -F "folder=$FOLDER_A" -F "title=UploadProbe" -F "author=AuthorZ" \
  -F "files=@$WORK_DIR/probe.html")
status_of POST "$BASE_URL/api/libraries/$LIB_A/scan" "${AUTH_ADMIN[@]}" > /dev/null
sleep 15
status_of GET "$BASE_URL/api/libraries/$LIB_A/items" "${AUTH_ADMIN[@]}" > /dev/null
ITEM_A=$(jq -r '.results[0].id // empty' "$WORK_DIR/body")

if [ "$UP" != "200" ]; then
  record "ST-04" "Uploaded HTML is not served inline as same-origin text/html" \
    "WSTG-BUSL-09, WSTG-INPV-02" "high" "pass" \
    "Upload of a .html file by a user holding only the upload permission was rejected (HTTP $UP)."
elif [ -z "$ITEM_A" ]; then
  record "ST-04" "Uploaded HTML is not served inline as same-origin text/html" \
    "WSTG-BUSL-09, WSTG-INPV-02" "high" "error" \
    "The file was accepted but no library item was produced, so serving behaviour could not be measured."
else
  status_of GET "$BASE_URL/api/items/$ITEM_A" "${AUTH_ADMIN[@]}" > /dev/null
  HTML_INO=$(jq -r '.libraryFiles[]? | select(.metadata.ext==".html") | .ino' "$WORK_DIR/body" | head -1)
  if [ -z "$HTML_INO" ]; then
    record "ST-04" "Uploaded HTML is not served inline as same-origin text/html" \
      "WSTG-BUSL-09, WSTG-INPV-02" "high" "pass" \
      "The .html file was accepted on upload but is not exposed as a library file."
  else
    FCODE=$(status_of GET "$BASE_URL/api/items/$ITEM_A/file/$HTML_INO" "${AUTH_LOW[@]}")
    CTYPE=$(grep -i '^content-type:' "$WORK_DIR/hdr" | tr -d '\r' | head -1 | cut -d' ' -f2-)
    CDISP=$(grep -ic '^content-disposition: *attachment' "$WORK_DIR/hdr")
    if [ "$CDISP" -gt 0 ] || ! echo "$CTYPE" | grep -qi 'text/html'; then
      record "ST-04" "Uploaded HTML is not served inline as same-origin text/html" \
        "WSTG-BUSL-09, WSTG-INPV-02" "high" "pass" \
        "Served with Content-Type '$CTYPE', attachment disposition present=$CDISP."
    else
      record "ST-04" "Uploaded HTML is not served inline as same-origin text/html" \
        "WSTG-BUSL-09, WSTG-INPV-02" "high" "fail" \
        "A user holding only the upload permission stored an .html file, and GET /api/items/:id/file/:ino returns it as HTTP $FCODE with Content-Type '$CTYPE' and no attachment disposition. Script in that file therefore runs in the application's own origin. The sibling route /file/:ino/download already sets an attachment disposition, so the safe behaviour exists but is not applied on this route."
    fi
  fi
fi

# ---------------------------------------------------------------------------
# ST-05  Library authorization on the media progress endpoints
# ---------------------------------------------------------------------------
CTRL_ITEM=$(status_of GET "$BASE_URL/api/items/$ITEM_B" "${AUTH_LOW[@]}")
PCODE=$(status_of PATCH "$BASE_URL/api/me/progress/$ITEM_B" "${AUTH_LOW[@]}" \
  -H 'Content-Type: application/json' -d '{"progress":0.5,"currentTime":30}')
GCODE=$(status_of GET "$BASE_URL/api/me/progress/$ITEM_B" "${AUTH_LOW[@]}")
STORED=$(jq -r '.libraryItemId // empty' "$WORK_DIR/body" 2>/dev/null)

if [ "$CTRL_ITEM" = "200" ]; then
  record "ST-05" "Media progress endpoints enforce library access" "WSTG-ATHZ-02" "medium" "error" \
    "The low-privilege user could read the library B item directly (HTTP $CTRL_ITEM), so the fixture does not represent an inaccessible library."
elif [ "$PCODE" = "403" ] || [ "$PCODE" = "404" ]; then
  record "ST-05" "Media progress endpoints enforce library access" "WSTG-ATHZ-02" "medium" "pass" \
    "Direct item access returned $CTRL_ITEM and the progress write returned $PCODE."
else
  record "ST-05" "Media progress endpoints enforce library access" "WSTG-ATHZ-02" "medium" "fail" \
    "GET /api/items/:id returns $CTRL_ITEM for this user, but PATCH /api/me/progress/:id returned $PCODE and the value reads back with GET returning $GCODE (libraryItemId='$STORED'). Item routes are bound through LibraryItemController.middleware, which checks library access; the /api/me/progress routes bind directly to MeController without it, so a user can confirm the existence of, and store state against, items in libraries they cannot see."
fi

# ---------------------------------------------------------------------------
# ST-06  Authentication on the cover art route
# ---------------------------------------------------------------------------
ANON=$(status_of GET "$BASE_URL/api/items/$ITEM_B/cover")
ANON_TYPE=$(grep -i '^content-type:' "$WORK_DIR/hdr" | tr -d '\r' | head -1 | cut -d' ' -f2-)
ANON_BYTES=$(wc -c < "$WORK_DIR/body" | tr -d ' ')
if [ "$ANON" = "401" ] || [ "$ANON" = "403" ]; then
  record "ST-06" "Cover art requires authentication" "WSTG-ATHZ-04" "medium" "pass" \
    "Unauthenticated GET /api/items/:id/cover returned $ANON."
else
  record "ST-06" "Cover art requires authentication" "WSTG-ATHZ-04" "medium" "fail" \
    "Unauthenticated GET /api/items/:id/cover returned HTTP $ANON with Content-Type '$ANON_TYPE' and $ANON_BYTES bytes of image data. The GET route is registered without LibraryItemController.middleware, unlike the POST, PATCH and DELETE handlers on the same path, so cover art for any item in any library is readable without a session."
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

[ -f "$BASELINE_FILE" ] || fatal "baseline file $BASELINE_FILE is missing; refusing to guess which failures are expected"

# `.id` must be bound before piping into the baseline object, otherwise `.`
# inside has() refers to known_failing rather than the result entry, and the
# comparison silently matches nothing, hiding every regression.
REGRESSIONS=$(jq -r --slurpfile b "$BASELINE_FILE" \
  '[.results[] | select(.status=="fail") | .id as $id | select(($b[0].known_failing | has($id)) | not) | $id] | join(" ")' \
  "$RESULTS_FILE")
ERRORED=$(jq -r '[.results[] | select(.status=="error") | .id] | join(" ")' "$RESULTS_FILE")
FIXED=$(jq -r --slurpfile b "$BASELINE_FILE" \
  '[.results[] | select(.status=="pass") | .id as $id | select($b[0].known_failing | has($id)) | $id] | join(" ")' \
  "$RESULTS_FILE")

if [ -n "$FIXED" ]; then
  log "NOTE: the baseline lists these as known-failing but they now pass: $FIXED"
  log "      remove them from $BASELINE_FILE so a future regression is caught."
fi

STATUS=0
if [ -n "$ERRORED" ]; then
  echo "::error::Security tests could not execute: $ERRORED. The harness or its fixtures are broken."
  STATUS=1
fi
if [ -n "$REGRESSIONS" ]; then
  echo "::error::Security regression detected in: $REGRESSIONS (failing, and not listed in the baseline)."
  STATUS=1
fi
if [ "$STATUS" -eq 0 ] && [ "$FAIL" -gt 0 ]; then
  log "$FAIL known-failing test(s) reported, recorded in $BASELINE_FILE. Not regressions."
fi
exit "$STATUS"
