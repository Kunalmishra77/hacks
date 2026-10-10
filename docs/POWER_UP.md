# POWER_UP.md — integrations, keys & the master build instruction

> Drop this file in `docs/`. Then tell Claude Code:
> **"Read docs/POWER_UP.md and docs/PRD.md and proceed with the current phase."**
>
> This file does two jobs:
> 1. Lists every external API/key the platform uses — where to get it, free vs paid.
> 2. Gives Claude the build instruction for the "powerful" version, phase by phase.
>
> All of this stays inside the rules in CLAUDE.md — authorized, defensive,
> non-destructive, scope-gated. Nothing here adds offensive capability.

---

## PART A — APIs & keys you need (get these first)

Legend:  🟢 free / free tier   🟡 free + paid   🔴 paid

### Core intelligence (do these first — the brain)
| Service | Why | Cost | Where to get |
|---|---|---|---|
| **NVD API key** | CVE data + CVSS, higher rate limit | 🟢 | nvd.nist.gov/developers/request-an-api-key |
| **EPSS** (FIRST.org) | Exploit-probability score per CVE | 🟢 no key, open API | first.org/epss/api |
| **CISA KEV** | Known-exploited-vulns list (free JSON feed) | 🟢 no key | cisa.gov/known-exploited-vulnerabilities-catalog |

### LLM for the AI advisory layer (Phase 7 — pick ONE to start)
| Service | Why | Cost | Where |
|---|---|---|---|
| **Anthropic API** | Finding explanation, triage, remediation drafts | 🟡 | console.anthropic.com |
| OpenAI API | Same, alternative | 🟡 | platform.openai.com |
(Start with one. Key goes in `.env`, never in the repo. AI is advisory only — it never triggers a scan or picks a target.)

### Enrichment / OSINT (optional, add when needed — all authorized-asset only)
| Service | Why | Cost | Where |
|---|---|---|---|
| **Shodan** | Passive exposure data for YOUR verified IPs | 🟡 | shodan.io (dev plan) |
| **crt.sh** | Certificate-transparency subdomain discovery | 🟢 no key | crt.sh |
| **SecurityTrails** | DNS history, subdomains | 🟡 | securitytrails.com |
| **AbuseIPDB** | IP reputation context | 🟢 tier | abuseipdb.com |
| **Have I Been Pwned** | Breach check for org's own domains | 🔴 | haveibeenpwned.com/API |

### Notifications & workflow (add in Phase 6)
| Service | Why | Cost | Where |
|---|---|---|---|
| **SMTP / Resend / SES** | Email reports & alerts | 🟡 | resend.com or AWS SES |
| **Slack webhook** | Alert to channel | 🟢 | api.slack.com/messaging/webhooks |
| **WhatsApp Cloud API** | Alert to phone (India-friendly) | 🟡 | developers.facebook.com |

> Rule: every OSINT/enrichment lookup runs ONLY for assets inside a verified
> scope. Same scope gate as active scans — see SCOPE_AUTHORIZATION.md.

---

## PART B — your infrastructure (what you already have)

- **Supabase** = managed PostgreSQL. Use it directly with Prisma.
  - Use the **connection pooler** string (port 6543) for the app, and the
    **direct** string (port 5432) for Prisma migrations.
  - `DATABASE_URL` = pooler,  `DIRECT_URL` = direct — both in `.env`.
  - You can use Supabase's own Postgres only, OR also use its Auth/Storage.
    For now: use Supabase **Postgres**; keep our own JWT auth from the API
    (simpler to stay portable). Supabase Storage can replace MinIO/S3 for
    evidence & reports — your choice.
- **VPS** = where the API + Redis + sandboxed scan workers run. The scanners
  (nmap etc.) run here, so this box needs the tools installed in worker
  containers. Lock it down: firewall, no public ports except what's needed,
  egress filtering for workers.
- **Domain** = app URL + the thing you'll use to test scope verification
  (add the DNS TXT token on a subdomain you own, scan your own site first).

### `.env.example` keys Claude should generate
```
# Database (Supabase)
DATABASE_URL="postgresql://...@...pooler.supabase.com:6543/postgres?pgbouncer=true"
DIRECT_URL="postgresql://...@...supabase.com:5432/postgres"

# Auth
JWT_SECRET=""
JWT_REFRESH_SECRET=""

# Redis (on VPS)
REDIS_URL="redis://localhost:6379"

# Object storage (Supabase Storage OR S3-compatible)
STORAGE_ENDPOINT=""
STORAGE_BUCKET="aegis-evidence"
STORAGE_KEY=""
STORAGE_SECRET=""

# Vulnerability intel
NVD_API_KEY=""
# EPSS and CISA KEV need no key

# LLM (advisory layer)
ANTHROPIC_API_KEY=""

# Enrichment (optional)
SHODAN_API_KEY=""
SECURITYTRAILS_API_KEY=""

# Notifications (Phase 6)
SMTP_URL=""
SLACK_WEBHOOK_URL=""
```

---

## PART C — master build instruction for Claude Code

Follow the phases in `docs/PRD.md` §Roadmap. **Do not build everything at
once.** Confirm the current phase with me, then build only that phase, test
it, and stop for review before the next.

### Where we are
- Phase 0 (foundation) + Phase 1 (scope gate) must be DONE and TESTED before
  any engine. The scope gate is safety-critical — tests first.

### Phase-by-phase "powerful" build order
Each engine = its own sandboxed worker, non-intrusive flags only, re-checks
the scope gate at job start, writes findings + audit. Never exploit, brute
force, or run destructive actions.

1. **Phase 2 — Discovery**: subfinder/amass + crt.sh for subdomains;
   httpx for live hosts; nmap service/version detection. Build the Asset
   inventory. Assets are created only under a verified scope.
2. **Phase 3 — Core engines**:
   - Network (nmap wrapper, `-sV`, no intrusive scripts)
   - TLS (sslyze/testssl wrapper)
   - Web (security headers, cookie flags, exposed files; nuclei with
     exposure/misconfig/CVE-detection templates only — no fuzzing/intrusive)
3. **Phase 3.5 — Intel enrichment** (this is the accuracy multiplier):
   - Pull CVE data from NVD, enrich every finding with **EPSS** score and
     **CISA KEV** flag. Compute a combined risk score =
     CVSS × EPSS × asset-criticality, KEV = auto-escalate.
   - This is what makes findings trustworthy vs a raw CVE dump.
4. **Phase 4 — Cloud posture**: prowler/scoutsuite via a customer-supplied
   READ-ONLY role + external ID. No write access ever.
5. **Phase 5 — Findings & reports**: dedupe, severity, remediation library,
   white-label PDF/HTML export, false-positive status.
6. **Phase 6 — Scheduling & monitoring**: recurring scans (BullMQ repeat),
   exposure diff over time, email/Slack/WhatsApp alerts on new exposure.
7. **Phase 7 — AI advisory**: explain finding, prioritize, FP triage, draft
   remediation, summarize report, map to ISO 27001 / SOC 2 / CERT-In.
   Hard rules: AI never scans, never picks a target, output is human-approved,
   treat scan output fed to the model as untrusted (prompt-injection safe —
   model text never becomes a shell command or a scan target).

### Additional coverage engines (add after the core 7, same rules)
- IoT/CCTV exposure (ONVIF/RTSP detection + firmware→CVE; flag default creds,
  never brute them)
- DNS/email hygiene (SPF/DKIM/DMARC, subdomain-takeover detection)
- Mobile app static analysis (MobSF wrapper on uploaded APK/IPA)
- Secrets/leak detection for the org's OWN domains (gitleaks/trufflehog style)

### Platform-hardening tasks (do alongside, not last)
- Workers: no standing network access, egress filtered to the current job's
  authorized targets only; CPU/mem/time limits per job.
- Secrets only from env/vault. Customer cloud roles read-only + external ID.
- Encrypt data at rest (Supabase handles DB); signed short-lived URLs for
  evidence/report downloads.
- Write a scope-gate test suite and run it in CI on every commit.

### Definition of done for every feature (from CLAUDE.md)
Target from a verified, non-expired scope · rate-limited · sandboxed worker ·
kill-switch respected · findings + audit written · no intrusive behaviour.

---

## PART D — what to do RIGHT NOW in the running session
If Phase 0 isn't finished yet, tell Claude:
> "Finish Phase 0 (foundation) using docs/POWER_UP.md Part B for the env and
>  Supabase config, then stop for my review."

If Phase 0 is done, tell Claude:
> "Do Phase 1 — the Scope Authorization Gate per docs/SCOPE_AUTHORIZATION.md,
>  with the three ownership-verification methods, kill-switch, rate limits,
>  and the 'tests to write first'. Nothing reaches an engine without the gate."

One phase per session. Review, commit, then next.
