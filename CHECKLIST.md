# Final Submission Checklist

Mark each: **Done / Incomplete / Not Done**

## Part 1 — Pipeline Design
- [ ] CI/CD platform selected & self-hosted runner registered on-premise — ___
- [ ] Security test cases cover: app functionality / API endpoints / Lab 2–5 threats — ___
- [ ] Static analysis integrated (Semgrep + ESLint-security) — ___
- [ ] OSS dependency/image scanning integrated (npm audit, Trivy) — ___
- [ ] Developer notification working (Slack + GitHub Issue) — ___
- [ ] Optional enhancements (gitleaks commit scanning) — ___
- [ ] Written test-case justification drafted — ___

## Part 2 — Automated Secure Deployment
- [ ] Deployment automated via Ansible (`ansible/deploy.yml`) — ___
- [ ] Containerized with hardened Docker Compose — ___
- [ ] Config management scripted, not manual — ___
- [ ] Network/access controls applied (Caddy admin-path restriction) — ___
- [ ] Debug mode disabled, HTTPS enforced, secure headers set — ___
- [ ] Post-deployment validation script passes — ___

## Part 3 — Collaboration & Bug Reporting
- [ ] At least one bug reported and approved by maintainers — ___
- [ ] Reproducible steps documented — ___
- [ ] Responsible disclosure followed — ___
- [ ] Developer reuse evidence collected (screenshots/transcripts, redacted) — ___
- [ ] Each student submitted their OWN bug report — ___
- [ ] Ongoing collaboration evidence for every deliverable (Discussions/Discord, redacted) — ___

## Part 4 — Maintenance Documentation
- [ ] `MAINTENANCE.md` completed — ___

## Part 5 — Final Report & Demo
- [ ] Report in Springer template, PDF, AODA-compliant — ___
- [ ] Report includes all 7 required sections — ___
- [ ] Video 10–15 min, main screen + speaker screen, live tool demos — ___
- [ ] Slides submitted alongside video, video follows slides — ___
- [ ] All group members' videos are the same length — ___

## Submission Files (individually, no ZIP)
- [ ] Final Report (PDF)
- [ ] CI/CD config files (.yml/.json)
- [ ] Developer feedback evidence (PDF/screenshots)
- [ ] Bug report (PDF) — individual
- [ ] Pipeline maintenance guide (PDF)
- [ ] Video demonstration (MP4 or link)
