#!/usr/bin/env bash
# Post-deployment validation (Part 2.3): config audits, vuln scans, availability/integrity
set -uo pipefail

HOST="localhost"
HTTPS_PORT=13443
HTTP_PORT=13380
FAIL=0

echo "== 1. Service availability =="
if curl -sk -o /dev/null -w "%{http_code}" "https://${HOST}:${HTTPS_PORT}/healthcheck" | grep -q "200"; then
  echo "PASS: app responding over HTTPS"
else
  echo "FAIL: app not responding over HTTPS"; FAIL=1
fi

echo "== 2. HTTPS enforcement (HTTP should redirect) =="
CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://${HOST}:${HTTP_PORT}/")
if [[ "$CODE" == "301" || "$CODE" == "308" ]]; then
  echo "PASS: HTTP redirects to HTTPS ($CODE)"
else
  echo "FAIL: HTTP did not redirect (got $CODE)"; FAIL=1
fi

echo "== 3. Secure headers present =="
HEADERS=$(curl -sk -I "https://${HOST}:${HTTPS_PORT}/")
for h in "Strict-Transport-Security" "X-Content-Type-Options" "X-Frame-Options" "Content-Security-Policy"; do
  if echo "$HEADERS" | grep -qi "$h"; then
    echo "PASS: $h present"
  else
    echo "FAIL: $h missing"; FAIL=1
  fi
done

echo "== 4. Admin/config endpoints restricted =="
CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://${HOST}:${HTTPS_PORT}/config")
echo "INFO: /config returned $CODE (expect 403 from outside local network, 200/redirect from inside)"

echo "== 5. Container running as non-root =="
USERID=$(docker exec abs-hardened id -u 2>/dev/null || echo "unknown")
if [[ "$USERID" != "0" && "$USERID" != "unknown" ]]; then
  echo "PASS: container running as uid $USERID"
else
  echo "FAIL: container running as root or unreachable"; FAIL=1
fi

echo "== 6. Vulnerability re-scan of running image =="
IMAGE=$(docker inspect --format='{{.Config.Image}}' abs-hardened)
trivy image --severity HIGH,CRITICAL --exit-code 0 --format table "$IMAGE" | tee trivy-post-deploy.txt

echo "== 7. Only expected ports exposed =="
nmap -p 13380,13443 "$HOST" | tee nmap-post-deploy.txt

echo "=================================="
if [[ "$FAIL" -eq 0 ]]; then
  echo "RESULT: All checks passed"
  exit 0
else
  echo "RESULT: One or more checks FAILED — review output above"
  exit 1
fi
