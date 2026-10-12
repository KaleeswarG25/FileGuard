# FileGuard MVP

Local file malware triage app using Git, Docker and Jenkins.

## Run
1. Copy `.env.example` to `.env`.
2. Optionally set `VIRUSTOTAL_API_KEY` in `.env`.
3. Run `docker compose up --build -d`.
4. Open http://localhost:5000; health check is `/health`.

VirusTotal integration performs a SHA-256 hash lookup only. It never uploads file contents. VirusTotal warns that queried indicators may be added to its dataset; do not query hashes of confidential/sensitive files. API docs: https://docs.virustotal.com/reference/file-info.

## Git
```bash
git init
git add .
git commit -m "Initial FileGuard MVP"
git branch -M main
git remote add origin <YOUR_GIT_REMOTE_URL>
git push -u origin main
```
Never commit `.env`.

## Jenkins
Create a Pipeline job connected to this repository and use `Jenkinsfile`. The agent needs Python 3, Docker CLI/daemon access and curl. Access to the Docker socket is highly privileged; use a dedicated local agent and trusted jobs only.

## MVP limitations
Reports are held in memory and disappear after a restart; this is not yet suitable for multiple workers or public deployment. Static checks are limited, heuristic results can be wrong, and the score is not a probability. No uploaded file is executed. Do not expose publicly without rate limits, stronger isolation and abuse controls.

## Phase 2: improved static triage

The enhanced analyzer adds bounded header-signature identification, filename-extension consistency checks, Shannon entropy over the inspected sample, printable-string offsets, and evidence offsets for heuristic matches. It still does not execute uploaded files or claim a definitive malware verdict. Header recognition is partial format identification, not full file validation. The first 2 MiB are used for entropy, string extraction, and heuristic checks.

After updating an existing checkout, rebuild the image:

```powershell
git status
docker compose up --build -d
docker compose ps
docker compose logs --tail 100
Invoke-RestMethod http://localhost:5000/health
```

Reports are currently stored in process memory, so previously generated report links may stop working after container restart. This is expected for the MVP.
