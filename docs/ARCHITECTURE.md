# ARCHITECTURE.md — Aegis ASM

## 1. High-level shape
```
Next.js dashboard
      │  (HTTPS, JWT)
API gateway (Node/TS) ── Auth + RBAC ── Multi-tenant (org→team)
      │
Scope Authorization Gate  ◄── the one choke point (see SCOPE_AUTHORIZATION.md)
      │  (enqueue only authorized jobs)
Redis + BullMQ queue
      │
Sandboxed workers (Docker)  ── one job = one engine run, resource-limited
      │                         re-checks the gate at start
      ├─ discovery worker      (subdomains, live hosts, services)
      ├─ network engine        (nmap wrapper)
      ├─ tls engine            (sslyze/testssl wrapper)
      ├─ web engine            (headers, exposure, nuclei non-intrusive, CVE)
      ├─ cloud engine          (prowler/scoutsuite, read-only role)
      └─ deps engine           (trivy SBOM + CVE)
      │
PostgreSQL (assets, scopes, scans, findings, audit)  +  S3 (evidence, reports)
CVE/NVD mirror (version→CVE + CVSS)
AI assist service (advisory only, human-in-loop)
```

## 2. Engines = wrappers, not reimplementations
Each engine is a thin, sandboxed adapter that:
1. Receives an authorized job (org, scope, asset, engine, params).
2. Re-validates the gate.
3. Invokes an established tool with **non-intrusive flags only**.
4. Normalizes output → `Finding` records (type, severity, evidence, CVE refs).
5. Writes findings + audit; uploads raw evidence to object storage.

Tools invoked (respect their licences; do not vendor their source):
- nmap (service/version detection) · sslyze or testssl.sh · nuclei
  (exposure/misconfig/CVE-detection templates only, no intrusive/fuzzing) ·
  trivy (SBOM + CVE) · prowler / scoutsuite (cloud posture, read-only).

Keep each engine in its own container image so a broken/heavy tool can't
affect the API or other engines. Set CPU/mem/time limits per job.

## 3. Data model (Prisma sketch — extend as needed)
- Org, User, Membership(role), Team
- Scope, Asset (see SCOPE_AUTHORIZATION.md)
- Scan, Finding { id, scan_id, asset_id, type, severity, cvss?, cve_refs[],
  title, evidence_url, remediation, status: 'open'|'triaged'|'fixed'|'fp' }
- Report { id, org_id, scope_id, format, storage_url, created_by }
- AuditEvent (append-only)
- ApiKey (hashed), ScanSchedule (cron, scope, engines)

## 4. Suggested folder structure (monorepo)
```
aegis/
├── CLAUDE.md
├── FIRST_PROMPT.md
├── docs/            PRD.md · ARCHITECTURE.md · SCOPE_AUTHORIZATION.md
├── .env.example
├── docker-compose.yml        # postgres, redis, minio, api, worker (dev)
├── package.json              # workspaces
├── apps/
│   ├── web/                  # Next.js dashboard
│   └── api/                  # Node/TS API + scope gate + queue producer
├── workers/
│   ├── discovery/
│   ├── network/
│   ├── tls/
│   ├── web/
│   ├── cloud/
│   └── deps/
├── packages/
│   ├── db/                   # Prisma schema + client
│   ├── core/                 # scope gate, RBAC, audit, types (shared)
│   └── cve/                  # NVD mirror + matching
└── infra/                    # dockerfiles, k8s (later), CI
```

## 5. Security of the platform itself
- Secrets in a vault / env, never in repo. Customer cloud roles are
  read-only + external-ID scoped.
- Workers have no standing network access beyond the authorized target set
  for the current job; egress filtered.
- All customer data encrypted at rest (DB + object storage) and in transit.
- Signed, short-lived URLs for evidence/report download.

## 6. AI assist (Phase 7 — advisory only)
Allowed: explain a finding in plain language, prioritize by exploitability +
asset value, flag likely false positives, draft remediation steps, summarize
a report, map findings to compliance controls.
Hard rules:
- AI never triggers a scan or chooses a new target autonomously.
- AI output is a suggestion a human approves; findings of record come from
  engines, not from the model.
- Treat scan output/logs fed to the model as untrusted (prompt-injection
  risk): never let model text become a shell command or a scan target.
- Show confidence + source; keep a human in the loop for anything actionable.

## 7. Build order (mirror PRD roadmap)
Foundation → **Scope gate (+tests)** → discovery → engines → cloud →
findings/reports → scheduling → AI. Do not build an engine before the gate
protecting it is tested.
