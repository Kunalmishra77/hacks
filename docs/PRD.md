# PRD — Aegis ASM (Authorized Security Assessment Platform)

## 1. Problem
Teams run a scatter of CLI tools (nmap, testssl, trivy, prowler) manually,
with no central asset inventory, no scope control, no history, and messy
reporting. Small businesses and consultants can't afford heavy enterprise
suites and don't need offensive tooling — they need to know *what is
exposed, what is misconfigured, what known CVEs apply, and how to fix it*
for assets they own.

## 2. Product
A multi-tenant SaaS that:
- keeps an **asset inventory** per organization,
- lets users define **authorized scopes** (domains / IP ranges / cloud
  accounts) with **ownership verification**,
- runs **non-intrusive assessment scans** against authorized assets,
- matches findings to **CVE/NVD + config best practices**,
- produces **risk-scored findings and shareable reports** with remediation,
- keeps a full **audit trail**.

## 3. Explicit non-goals (never build)
- Scanning of arbitrary / unverified targets.
- Exploitation, brute-forcing, payload injection, credential attacks.
- Persistence, C2, stealth, malware generation.
- Any destructive or intrusive action against a live system.
- Manipulating physical / OT / traffic infrastructure.
(These would turn a defensive product into an offensive weapon. Out of scope.)

## 4. Target users
- Small/mid businesses securing their own web + cloud footprint.
- Security consultants / small MSSPs running authorized assessments for clients.
- Dev/ops teams wanting continuous exposure monitoring.

## 5. Core user flows
1. **Onboard** → create org, invite team, set roles.
2. **Add scope** → enter domain/IP/cloud account → verify ownership
   (DNS TXT token, HTTP file token, or cloud read-only role) → scope becomes
   "authorized".
3. **Discover** → enumerate assets under the verified scope (subdomains,
   live hosts, open services, cloud resources).
4. **Assess** → run selected non-intrusive engines against discovered assets.
5. **Review** → findings list, severity, evidence, remediation.
6. **Report** → export PDF/HTML; share with team/client.
7. **Monitor** → schedule recurring scans; diff new exposures over time.

## 6. Roles (RBAC)
- Owner: billing, org settings, delete org.
- Admin: manage scopes, approve high-impact scans, manage members.
- Analyst: create/run scans on authorized scopes, view findings.
- Viewer: read-only findings + reports.

## 7. MVP scope (Level-1 only)
Assessment engines, all non-intrusive:
- **Network**: host/port/service + version identification (nmap wrapper).
- **TLS**: protocol/cipher/cert hygiene (sslyze/testssl wrapper).
- **Web**: HTTP security headers, cookie flags, exposed files/dirs,
  version→CVE matching; nuclei limited to non-intrusive
  exposure/misconfig/CVE-detection templates.
- **Cloud posture**: read-only config audit via customer-supplied
  least-privilege role (prowler/scoutsuite wrapper) for AWS/Azure/GCP.
- **Dependencies/containers**: SBOM + known-CVE scan (trivy wrapper).
- **CVE intel**: local mirror of NVD feed for version matching + CVSS.
- **Risk scoring + reporting + audit log.**

## 8. Roadmap (phased — build in this order)
- **Phase 0 — Foundation**: repo, CI, auth, org/team/RBAC, DB schema,
  audit log skeleton. No scanning yet.
- **Phase 1 — Scope gate**: scope model + 3 ownership-verification methods
  + kill-switch + rate limits. Fully tested. (Safety-critical.)
- **Phase 2 — Discovery**: subdomain + live-host + service discovery
  worker, asset inventory UI.
- **Phase 3 — Assessment engines**: network, TLS, web (as above), one at
  a time, each as a sandboxed worker.
- **Phase 4 — Cloud posture**: read-only cloud connectors + prowler engine.
- **Phase 5 — Findings & reports**: severity, dedupe, remediation library,
  PDF/HTML export.
- **Phase 6 — Scheduling & monitoring**: recurring scans, exposure diffs,
  notifications.
- **Phase 7 — AI assist (advisory)**: explain findings, prioritize,
  false-positive triage, draft remediation. Human-approved, never
  autonomous scanning. See ARCHITECTURE §AI.

## 9. Success metrics
- Time from "add scope" to "first verified finding".
- % findings with actionable remediation.
- Zero scans executed against unverified scopes (must always be 0).
- Report generation time; recurring-scan retention.

## 10. Compliance / legal posture (not legal advice)
- Enforce authorization at product level (this is the key control).
- Terms of Service: user warrants they own/are authorized for every scope.
- Keep audit logs as evidence of authorized activity.
- Get professional legal review before commercial launch (India IT Act;
  and GDPR/UK/US considerations if serving those regions).
