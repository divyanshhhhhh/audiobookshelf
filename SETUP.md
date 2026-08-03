# DevSecOps Project Setup Guide — Audiobookshelf

Target app: `advplyr/audiobookshelf` (your running container: `abs-patch-test`, host port 13380)
Host: your Ubuntu Docker box (the one `docker ps` was run on)

This assumes you're at ~28% and need: pipeline design, static analysis, dependency
scanning, notifications, hardened automated deployment, validation, and the
bug/collaboration evidence trail. Follow this top to bottom.

---

## 1. Install everything (run once on your Ubuntu host)

```bash
# Base tools
sudo apt update
sudo apt install -y git curl wget unzip build-essential python3-pip python3-venv \
  ansible nmap jq

# Node.js (Audiobookshelf is Node/Express + Vue/Nuxt frontend) — use NodeSource LTS
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
node -v && npm -v

# Semgrep (SAST)
python3 -m pip install --user semgrep
semgrep --version

# Trivy (container image + filesystem/dependency vulnerability scanner)
sudo apt install -y wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo gpg --dearmor -o /usr/share/keyrings/trivy.gpg
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt update && sudo apt install -y trivy

# gitleaks (secrets scanning — for "commit policy enforcement" optional enhancement)
wget https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_8.18.4_linux_x64.tar.gz
tar -xzf gitleaks_8.18.4_linux_x64.tar.gz gitleaks
sudo mv gitleaks /usr/local/bin/
rm gitleaks_8.18.4_linux_x64.tar.gz
gitleaks version

# OWASP ZAP (API/dynamic security testing — covers "API endpoints" + "threat scenarios")
# Easiest: run via Docker, no local install needed (see workflow file, uses zaproxy action)

# GitHub CLI (handy for issues/PRs from terminal)
type -p curl >/dev/null && sudo apt install -y curl
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
sudo chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt update && sudo apt install -y gh
gh auth login
```

Ansible Vault ships with `ansible`, so no separate install needed for that.

---

## 2. Git workflow, from absolute zero

You need **two tracks**:
- **Track A (your pipeline code)** — lives in your own fork, this is what you submit.
- **Track B (the bug)** — a small, separate branch/PR you eventually send **upstream**
  to the real `advplyr/audiobookshelf` maintainers (this is your "confirmed bug" evidence).

### 2.1 Fork and clone

```bash
# On GitHub.com: click "Fork" on https://github.com/advplyr/audiobookshelf
# Then locally:
cd ~/projects
git clone https://github.com/<your-username>/audiobookshelf.git
cd audiobookshelf
git remote add upstream https://github.com/advplyr/audiobookshelf.git
git remote -v   # confirm origin = your fork, upstream = advplyr
```

### 2.2 Branch strategy

```bash
git checkout -b security/devsecops-pipeline
```

Everything below (workflows, ansible, scripts) gets added on this branch.

### 2.3 Commit conventions (keeps your report/checklist clean)

Use prefixes so graders can trace rubric items to commits:
```
git commit -m "ci: add semgrep + eslint-security static analysis"
git commit -m "ci: add trivy dependency + image scanning"
git commit -m "ci: add zap baseline scan for API endpoints"
git commit -m "ci: add slack/github-issue notification on findings"
git commit -m "deploy: add ansible playbook for hardened local deployment"
git commit -m "deploy: add docker-compose hardened config + caddy https headers"
git commit -m "docs: add maintenance guide and bug report template"
```

### 2.4 Push and open a PR *within your own fork* (base repo, not upstream)

```bash
git push -u origin security/devsecops-pipeline
gh pr create --repo <your-username>/audiobookshelf \
  --base main --head security/devsecops-pipeline \
  --title "DevSecOps pipeline: SAST, SCA, DAST, notifications, hardened deploy" \
  --body "Final project pipeline. See SETUP.md."
```
This PR (with your commit history + any CI run logs) is your "pipeline design"
evidence for the report/video — no need to merge it upstream, it's yours.

### 2.5 Self-hosted runner (so the pipeline runs on-premise, not in the cloud)

The rubric requires **on-premise execution**. GitHub Actions itself is fine to
use as the orchestrator, but the *runner* must be your machine, not GitHub's
cloud VMs. Register your box as a self-hosted runner:

```bash
# In GitHub: your fork > Settings > Actions > Runners > "New self-hosted runner"
# Copy the generated token, then on your Ubuntu host:
mkdir ~/actions-runner && cd ~/actions-runner
curl -o actions-runner-linux-x64.tar.gz -L https://github.com/actions/runner/releases/latest/download/actions-runner-linux-x64-2.319.1.tar.gz
tar xzf ./actions-runner-linux-x64.tar.gz
./config.sh --url https://github.com/<your-username>/audiobookshelf --token <TOKEN_FROM_GITHUB>
sudo ./svc.sh install
sudo ./svc.sh start
```
The workflow file below is already set to `runs-on: self-hosted`.

### 2.6 When you find a real bug (Part 3 requirement)

```bash
git checkout main
git pull upstream main
git checkout -b bug/<short-description>
# make the minimal fix
git commit -m "fix: <describe the vulnerability fix>"
git push -u origin bug/<short-description>
gh pr create --repo advplyr/audiobookshelf --base master --head <your-username>:bug/<short-description> \
  --title "Security: <short description>" \
  --body "Reproduction steps, impact, and fix. See attached bug report."
```
Keep the PR/issue link — that's your "approved by maintainers" evidence, and
each group member still writes their **own** individual bug report doc
(rubric requires this individually even if you found it together).

---

## 3. Secrets & the "root password" question

Don't try to vault an *empty* root password — remove it as an attack surface instead:

```bash
# Inside the container you use for testing (abs-patch-test), disable password login,
# use key-based SSH if you need shell access at all:
docker exec -it abs-patch-test passwd -l root   # locks the password (no login via password)
```

For real secrets your pipeline needs (Slack webhook, GitHub token, ZAP config):

- **CI-facing secrets** → GitHub encrypted secrets: repo Settings → Secrets and
  variables → Actions → New repository secret (`SLACK_WEBHOOK_URL`, etc). Never
  put these in files committed to git.
- **Local-only secrets** (e.g., Ansible vault password) → `ansible-vault`:

```bash
cd ~/projects/audiobookshelf/ansible
ansible-vault create secrets.yml
# add: slack_webhook: "https://hooks.slack.com/..."
echo "your-vault-password" > ~/.abs_vault_pass
chmod 600 ~/.abs_vault_pass
echo "vault_password_file = ~/.abs_vault_pass" >> ansible.cfg
```
`secrets.yml` stays encrypted at rest in git; `~/.abs_vault_pass` never gets committed
(add it to `.gitignore` by path, it's outside the repo anyway).

---

## 4. File map (what's in this bundle, where it goes in your fork)

```
audiobookshelf/
├── .github/workflows/security-pipeline.yml   <- CI/CD pipeline (this bundle)
├── ansible/
│   ├── deploy.yml                            <- deployment playbook
│   └── inventory.ini
├── docker/
│   ├── docker-compose.hardened.yml           <- hardened runtime config
│   └── Caddyfile                             <- HTTPS + secure headers
├── scripts/
│   └── post-deploy-validate.sh               <- automated post-deploy checks
├── MAINTENANCE.md
├── BUG_REPORT_TEMPLATE.md
└── CHECKLIST.md
```

Copy each file from this bundle into the matching path in your cloned fork, then
commit per the conventions in 2.3.

---

## 5. Rubric-to-deliverable map (so nothing gets missed)

| Rubric item (pts) | Where it's satisfied |
|---|---|
| Pipeline design & implementation (15) | `security-pipeline.yml` |
| Security testing coverage & justification (15) | `security-pipeline.yml` (ZAP job) + you write justification in final report citing Labs 2–5 |
| Static analysis & OSS scanning (10) | `security-pipeline.yml` (semgrep, eslint-security, trivy, npm audit) |
| Developer notification system (10) | `security-pipeline.yml` (Slack + GitHub Issue steps) |
| Automated secure deployment (15) | `ansible/deploy.yml` + `docker-compose.hardened.yml` + `Caddyfile` |
| Confirmed bug report & disclosure (10) | Section 2.6 + `BUG_REPORT_TEMPLATE.md` (individual, per student) |
| Developer reuse evidence (10) | Collect screenshots/transcripts of maintainer discussion — see `MAINTENANCE.md` footer |
| Pipeline maintenance docs (10) | `MAINTENANCE.md` |
| Final report & video (5) | Use `CHECKLIST.md` as your literal submission checklist; Springer template for the report |

Full grade also needs the **Collaboration Requirement** evidence (GitHub
Discussions/Discord screenshots, redacted) — start posting in Audiobookshelf's
GitHub Discussions now, not right before the deadline, so you have a real thread
to screenshot.
