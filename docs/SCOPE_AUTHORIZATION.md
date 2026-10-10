# SCOPE_AUTHORIZATION.md — the safety-critical core

> This is the single choke point that keeps Aegis a defensive product.
> No scan of any kind may reach an engine without passing this gate.
> Build and fully test this BEFORE any discovery/assessment engine.

## Principle
A scan may only run against a **target** that resolves to an **authorized
scope** whose ownership has been **verified** and is **not expired or revoked**.
There is exactly one function every scan path calls; there is no bypass.

## Data model (concept)
- `Scope { id, org_id, type: 'domain'|'ip_range'|'cloud_account',
   value, status: 'pending'|'verified'|'expired'|'revoked',
   verification_method, verified_at, expires_at, created_by }`
- `Asset { id, scope_id, kind, address, first_seen, last_seen }`
  (assets are only created under a verified scope)
- `Scan { id, org_id, scope_id, engine, status, requested_by,
   approved_by?, killed_at?, created_at }`
- `AuditEvent { id, org_id, actor, action, scope_id?, scan_id?,
   payload, created_at }` (append-only)

## Ownership verification methods (MVP — pick per scope type)
1. **Domain — DNS TXT**: user adds `aegis-verify=<random-token>` TXT record;
   platform resolves and matches. Re-check periodically.
2. **Domain/host — HTTP file**: user hosts `/.well-known/aegis-verify.txt`
   containing the token; platform fetches over HTTPS and matches.
3. **Cloud account — least-privilege role**: user creates a **read-only**
   role/service-principal with a platform-provided external ID; platform
   assumes it and confirms account identity. Read-only scope only.

Verification expires (e.g. 90 days) → scope must re-verify before new scans.

## The gate (pseudocode — enforce everywhere)
```
function authorizeTarget(orgId, target, engine, actor):
    scope = findScopeCovering(orgId, target)          # target ∈ scope.value
    assert scope exists                                # else REJECT (no scope)
    assert scope.org_id == orgId                       # tenant isolation
    assert scope.status == 'verified'                  # not pending/expired/revoked
    assert now < scope.expires_at
    assert engine in scope.allowed_engines
    assert not org.killSwitchEngaged
    assert withinRateLimit(orgId, scope, engine)
    if engine.requiresApproval and not scan.approved_by:
        return NEEDS_APPROVAL
    audit(actor, 'scan.authorized', scope, target, engine)
    return ALLOW
```
Every worker re-checks the gate at job start (defense in depth) — never trust
that the API already checked.

## Target-in-scope matching (be strict)
- Domain scope covers the apex + subdomains you explicitly enumerated and
  stored as assets — not arbitrary wildcards a user types at scan time.
- IP-range scope: target IP must fall inside the verified CIDR.
- Never accept a raw hostname/IP at scan time that isn't already an Asset
  under a verified Scope. Discovery creates Assets; scans target Assets.

## Controls
- **Kill-switch**: org-level and per-scan. Engaging it stops queued + running
  jobs and blocks new ones. Must be one click in UI and one API call.
- **Rate limits**: per-scope requests/sec and per-org concurrent scans, to
  avoid hammering targets (which can look like an attack even when authorized).
- **Approval workflow**: heavier engines (e.g. full port sweep) require an
  Admin approval before running.
- **Audit trail**: append-only, immutable. Every scope change, verification,
  scan authorization, kill-switch, and finding is recorded with actor + time.

## Tests to write first (Phase 1 done = these pass)
- Scan against unverified scope → rejected + audited.
- Scan against another org's verified scope → rejected (tenant isolation).
- Expired scope → rejected until re-verified.
- Kill-switch engaged → running jobs stop, new jobs blocked.
- Rate limit exceeded → throttled, not dropped silently.
- Worker with tampered job payload (target outside scope) → refuses at start.
