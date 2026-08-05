# Individual Security Bug Report

> Submit one of these per student, even if the bug was found collaboratively.
> Redact any credentials, tokens, or personal data from all screenshots before submission.

**Student name:**
**Project:** Audiobookshelf DevSecOps Pipeline
**Date discovered:**
**Discovery method:** (e.g., Semgrep finding / Trivy CVE / ZAP alert / manual review)

## 1. Vulnerability summary
One or two sentences: what is the flaw and what class does it belong to
(e.g., OWASP A01 Broken Access Control, A03 Injection)?

## 2. Affected component
- File(s)/endpoint(s):
- Version of Audiobookshelf tested:

## 3. Impact
- Confidentiality / Integrity / Availability impact:
- Who can exploit it (unauthenticated, authenticated user, admin-only)?
- Realistic worst case:

## 4. Reproduction steps
1.
2.
3.

Include exact requests (curl/HTTP), inputs, and expected vs. actual behavior.
Attach terminal/browser screenshots showing your own username/session (not a
copied screenshot) to prove you personally reproduced it.

## 5. Evidence
- [ ] Screenshot(s) attached, redacted
- [ ] Tool output attached (Semgrep/Trivy/ZAP excerpt)

## 6. Suggested fix
Describe or link the code change that resolves it.

## 7. Disclosure record
- Where reported (GitHub issue/PR link, private security advisory, email):
- Date reported:
- Maintainer response / approval (quote or link):
- Status: Reported / Acknowledged / Fixed / Disputed

## 8. Lessons learned
What would you check for earlier next time, and did the pipeline (Semgrep/
Trivy/ZAP) catch this automatically or did it require manual testing?
