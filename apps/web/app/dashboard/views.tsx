"use client";

import { useEffect, useState, type FormEvent } from "react";
import {
  api,
  can,
  type Asset,
  type Finding,
  type FindingStatus,
  type OrgSummary,
  type Role,
  type Scan,
  type Scope,
  type Severity,
  type SeveritySummary,
} from "@/lib/api";

type Act = (fn: () => Promise<unknown>, ok: string) => Promise<void>;

const KIND_LABEL: Record<Asset["kind"], string> = {
  DOMAIN: "Domain",
  SUBDOMAIN: "Subdomain",
  IP: "IP address",
  SERVICE: "Web service",
  CLOUD_RESOURCE: "Cloud account",
};
const ENGINE_LABEL: Record<Scan["engine"], string> = {
  DISCOVERY: "Asset discovery",
  NETWORK: "Port & service scan",
  TLS: "TLS check",
  WEB: "Web check",
  CLOUD: "Cloud posture",
  DEPS: "Dependencies",
};
const SCAN_STATUS: Record<Scan["status"], { label: string; tone: string }> = {
  PENDING_APPROVAL: { label: "Waiting for approval", tone: "text-wait" },
  QUEUED: { label: "Queued", tone: "text-wait" },
  RUNNING: { label: "Running", tone: "text-wait" },
  SUCCEEDED: { label: "Finished", tone: "text-ok" },
  FAILED: { label: "Failed", tone: "text-stop" },
  KILLED: { label: "Stopped", tone: "text-muted" },
  REJECTED: { label: "Rejected", tone: "text-stop" },
};
const SCOPE_STATUS: Record<Scope["status"], { label: string; tone: string }> = {
  PENDING: { label: "Not proven yet", tone: "text-wait" },
  VERIFIED: { label: "Proven", tone: "text-ok" },
  EXPIRED: { label: "Proof expired", tone: "text-stop" },
  REVOKED: { label: "Revoked", tone: "text-muted" },
};

const fmtDate = (s: string | null) => (s ? new Date(s).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" }) : "—");
const fmtTime = (s: string) => new Date(s).toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });

const btn = "rounded-md px-3 py-1.5 text-sm font-semibold disabled:opacity-40";
const btnPrimary = `${btn} bg-ink text-sheet hover:bg-ink/85`;
const btnQuiet = `${btn} border border-line hover:border-ink/50`;

// ── Kill-switch ────────────────────────────────────────────────────

/**
 * The one loud control. Stopping is two clicks (arm, then confirm within 5s)
 * and open to anyone who can run scans; allowing scans again is Admin-only.
 */
export function KillSwitch({ engaged, role, onChange }: { engaged: boolean; role: Role; onChange: (engaged: boolean) => void }) {
  const [armed, setArmed] = useState(false);
  useEffect(() => {
    if (!armed) return;
    const t = setTimeout(() => setArmed(false), 5000);
    return () => clearTimeout(t);
  }, [armed]);

  if (engaged) {
    return (
      <div className="flex items-center gap-3 rounded-md border-2 border-stop bg-stop px-3 py-1.5 text-sheet">
        <span className="text-sm font-semibold">All scans stopped</span>
        {can.releaseKillSwitch(role) && (
          <button onClick={() => onChange(false)} className="rounded bg-sheet px-2 py-0.5 text-xs font-semibold text-stop hover:bg-sheet/90">
            Allow scans again
          </button>
        )}
      </div>
    );
  }
  if (!can.runScans(role)) return <span className="text-sm text-muted">Scans allowed</span>;
  return (
    <button
      onClick={() => (armed ? (setArmed(false), onChange(true)) : setArmed(true))}
      className={`rounded-md border-2 border-stop px-3 py-1.5 text-sm font-semibold ${armed ? "bg-stop text-sheet" : "text-stop hover:bg-stop/10"}`}
    >
      {armed ? "Click again to stop every scan" : "Stop all scans"}
    </button>
  );
}

// ── Assets ─────────────────────────────────────────────────────────

const hostOf = (a: Asset) => (a.kind === "SERVICE" ? a.address.replace(/:\d+$/, "") : a.address);

/** Each host followed by its web services; the scope's own apex/IP group leads. */
function sortAssets(rows: Asset[]): Asset[] {
  const seedHost = rows.find((a) => a.kind === "DOMAIN" || a.kind === "IP")?.address;
  const key = (a: Asset) => [hostOf(a) === seedHost ? 0 : 1, hostOf(a), a.kind === "SERVICE" ? 1 : 0, a.address] as const;
  return [...rows].sort((x, y) => {
    const kx = key(x);
    const ky = key(y);
    return kx[0] - ky[0] || kx[1].localeCompare(ky[1]) || kx[2] - ky[2] || kx[3].localeCompare(ky[3]);
  });
}

function AssetDetail({ a }: { a: Asset }) {
  const m = (a.metadata ?? {}) as Record<string, unknown>;
  if (a.kind === "SERVICE") {
    const status = typeof m.statusCode === "number" ? m.statusCode : null;
    return (
      <span>
        {status !== null && <span className={status >= 400 ? "text-stop" : status >= 300 ? "text-wait" : "text-ok"}>{status}</span>}
        {typeof m.title === "string" && m.title && <span className="ml-2">{m.title}</span>}
        {typeof m.webServer === "string" && m.webServer && <span className="ml-2 text-muted">{m.webServer}</span>}
      </span>
    );
  }
  const ips = Array.isArray(m.ips) ? (m.ips as string[]) : [];
  return (
    <span className="text-muted">
      {ips.length > 0 && <span className="font-mono text-[13px] text-ink">{ips.slice(0, 3).join(", ")}{ips.length > 3 ? ` +${ips.length - 3}` : ""}</span>}
      {typeof m.cname === "string" && <span className="ml-2">via {m.cname}</span>}
      {m.private === true && <span className="ml-2 text-wait">Private address, not contacted</span>}
    </span>
  );
}

/** Which assessment engines make sense to run against a given asset kind. */
const ASSET_ENGINES: Record<Asset["kind"], ("WEB" | "TLS" | "NETWORK")[]> = {
  DOMAIN: ["WEB", "TLS", "NETWORK"],
  SUBDOMAIN: ["WEB", "TLS", "NETWORK"],
  IP: ["NETWORK", "WEB", "TLS"],
  SERVICE: ["WEB", "TLS", "NETWORK"],
  CLOUD_RESOURCE: [],
};
const CHECK_LABEL: Record<"WEB" | "TLS" | "NETWORK", string> = { WEB: "Web", TLS: "TLS", NETWORK: "Ports" };

export function AssetsView({
  org,
  scopes,
  assets,
  scans,
  killSwitch,
  findings,
  act,
  onGoToScopes,
}: {
  org: OrgSummary;
  scopes: Scope[];
  assets: Asset[];
  scans: Scan[];
  killSwitch: boolean;
  findings: Finding[];
  act: Act;
  onGoToScopes: () => void;
}) {
  const openByAsset = new Map<string, number>();
  for (const f of findings) {
    if (f.status === "OPEN" || f.status === "TRIAGED") openByAsset.set(f.assetId, (openByAsset.get(f.assetId) ?? 0) + 1);
  }
  const live = scopes.filter((s) => s.status !== "REVOKED");
  if (live.length === 0) {
    return (
      <section className="max-w-xl">
        <h1 className="text-2xl font-semibold tracking-tight">No assets yet</h1>
        <p className="mt-3 text-muted">
          Start by proving you own a domain or IP address. Aegis only looks inside boundaries you&apos;ve proven, then finds the
          subdomains and web services within them.
        </p>
        <button onClick={onGoToScopes} className={`${btnPrimary} mt-6`}>
          Add a domain
        </button>
      </section>
    );
  }

  return (
    <section className="flex flex-col gap-10">
      <h1 className="text-2xl font-semibold tracking-tight">Assets</h1>
      {live.map((scope) => {
        const rows = sortAssets(assets.filter((a) => a.scopeId === scope.id));
        const seed = rows.find((a) => a.kind === "DOMAIN" || a.kind === "IP");
        const running = scans.some((s) => s.scopeId === scope.id && s.engine === "DISCOVERY" && (s.status === "QUEUED" || s.status === "RUNNING"));
        const canDiscover =
          scope.status === "VERIFIED" && scope.allowedEngines.includes("DISCOVERY") && can.runScans(org.role) && !killSwitch && !!seed;
        const st = SCOPE_STATUS[scope.status];
        return (
          <div key={scope.id} className="border-l-4 border-boundary pl-4 sm:pl-6">
            <div className="flex flex-wrap items-baseline gap-x-4 gap-y-2">
              <h2 className="font-mono text-lg font-medium">{scope.value}</h2>
              <span className={`text-sm font-medium ${st.tone}`}>{st.label}</span>
              {scope.expiresAt && scope.status === "VERIFIED" && <span className="text-sm text-muted">re-check by {fmtDate(scope.expiresAt)}</span>}
              {scope.allowedEngines.includes("DISCOVERY") && (
                <button
                  disabled={!canDiscover || running}
                  onClick={() =>
                    act(
                      () => api(`/orgs/${org.id}/scans`, { method: "POST", body: { assetId: seed!.id, engine: "DISCOVERY" } }),
                      `Asset discovery queued for ${scope.value}.`,
                    )
                  }
                  className={`${btnQuiet} ml-auto`}
                  title={scope.status !== "VERIFIED" ? "Prove ownership first" : undefined}
                >
                  {running ? "Finding assets…" : "Find assets"}
                </button>
              )}
            </div>
            {rows.length === 0 ? (
              <p className="mt-3 text-sm text-muted">Prove ownership of this boundary to start finding assets in it.</p>
            ) : (
              <div className="mt-3 overflow-x-auto">
                <table className="w-full border-collapse text-sm sm:min-w-[640px]">
                  <thead>
                    <tr className="border-b border-line text-left text-muted">
                      <th className="py-2 pr-4 font-medium">Address</th>
                      <th className="hidden py-2 pr-4 font-medium sm:table-cell">Type</th>
                      <th className="hidden py-2 pr-4 font-medium sm:table-cell">What we saw</th>
                      <th className="py-2 pr-4 font-medium">Findings</th>
                      <th className="py-2 font-medium" />
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((a) => (
                      <tr key={a.id} className="border-b border-line/60 align-top">
                        <td className="py-2 pr-4">
                          <span className={`font-mono text-[13px] [overflow-wrap:anywhere] ${a.kind === "SERVICE" ? "pl-3 text-muted" : ""}`}>{a.address}</span>
                          <span className="mt-0.5 block text-xs text-muted sm:hidden">{KIND_LABEL[a.kind]}</span>
                          <span className="mt-1 block sm:hidden">
                            <AssetDetail a={a} />
                          </span>
                        </td>
                        <td className="hidden py-2 pr-4 whitespace-nowrap sm:table-cell">{KIND_LABEL[a.kind]}</td>
                        <td className="hidden py-2 pr-4 sm:table-cell">
                          <AssetDetail a={a} />
                        </td>
                        <td className="py-2 pr-4 whitespace-nowrap">
                          {openByAsset.get(a.id) ? (
                            <span className="font-medium">{openByAsset.get(a.id)} open</span>
                          ) : (
                            <span className="text-muted">—</span>
                          )}
                        </td>
                        <td className="py-2 text-right">
                          <span className="flex flex-wrap justify-end gap-1">
                          {ASSET_ENGINES[a.kind]
                            .filter((e) => scope.allowedEngines.includes(e))
                            .map((engine) => {
                              const running = scans.some((s) => s.assetId === a.id && s.engine === engine && (s.status === "QUEUED" || s.status === "RUNNING" || s.status === "PENDING_APPROVAL"));
                              const disabled = scope.status !== "VERIFIED" || !can.runScans(org.role) || killSwitch || running;
                              return (
                                <button
                                  key={engine}
                                  disabled={disabled}
                                  onClick={() =>
                                    act(
                                      () => api(`/orgs/${org.id}/scans`, { method: "POST", body: { assetId: a.id, engine } }),
                                      engine === "NETWORK"
                                        ? `Port scan needs an admin's approval; it's waiting in Scans.`
                                        : `${CHECK_LABEL[engine]} check queued for ${a.address}.`,
                                    )
                                  }
                                  className="rounded border border-line px-2 py-1 text-xs font-medium hover:border-ink/50 disabled:opacity-40"
                                  title={scope.status !== "VERIFIED" ? "Prove ownership first" : running ? "Already running" : `Run ${CHECK_LABEL[engine]} check`}
                                >
                                  {running ? `${CHECK_LABEL[engine]}…` : CHECK_LABEL[engine]}
                                </button>
                              );
                            })}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        );
      })}
    </section>
  );
}

// ── Ownership (scopes) ─────────────────────────────────────────────

function Copyable({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <span className="flex items-start gap-2">
      <code className="break-all rounded border border-line bg-sheet px-2 py-1 font-mono text-[13px]">{value}</code>
      <button
        type="button"
        onClick={async () => {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        }}
        className="shrink-0 text-xs text-muted underline underline-offset-2 hover:text-ink"
      >
        {copied ? "Copied" : "Copy"}
      </button>
    </span>
  );
}

function Instructions({ scope }: { scope: Scope }) {
  const v = scope.verification;
  if (!v) return null;
  return (
    <div className="mt-4 flex flex-col gap-4 text-sm">
      {v.DNS_TXT && (
        <div>
          <p className="font-medium">Option A: add a DNS TXT record</p>
          <p className="mt-1 text-muted">At your DNS provider, on {v.DNS_TXT.name}, add a TXT record with this value:</p>
          <div className="mt-2">
            <Copyable value={v.DNS_TXT.value} />
          </div>
        </div>
      )}
      {v.HTTP_FILE && (
        <div>
          <p className="font-medium">{v.DNS_TXT ? "Option B: " : ""}publish a file over HTTPS</p>
          <p className="mt-1 text-muted">Make this URL return the text below (no redirects):</p>
          <div className="mt-2 flex flex-col gap-2">
            <Copyable value={v.HTTP_FILE.url} />
            <Copyable value={v.HTTP_FILE.content} />
          </div>
        </div>
      )}
      {v.CLOUD_ROLE && (
        <div>
          <p className="font-medium">Grant a read-only role</p>
          <p className="mt-1 text-muted">
            Create the role below with the read-only policy, trusting our account, and require this external ID. Aegis can never
            use it to change anything.
          </p>
          <div className="mt-2 flex flex-col gap-2">
            <Copyable value={v.CLOUD_ROLE.roleArn} />
            <Copyable value={v.CLOUD_ROLE.externalId} />
            <Copyable value={v.CLOUD_ROLE.requiredPolicy} />
            <Copyable value={v.CLOUD_ROLE.trustedPrincipal} />
          </div>
        </div>
      )}
    </div>
  );
}

const METHOD_LABEL: Record<string, string> = { DNS_TXT: "DNS record", HTTP_FILE: "HTTPS file", CLOUD_ROLE: "read-only role" };

export function ScopesView({ org, scopes, act }: { org: OrgSummary; scopes: Scope[]; act: Act }) {
  const [type, setType] = useState<Scope["type"]>("DOMAIN");
  const [value, setValue] = useState("");
  const [roleArn, setRoleArn] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const manage = can.manageScopes(org.role);

  async function add(e: FormEvent) {
    e.preventDefault();
    await act(async () => {
      const res = await api<{ scope: Scope }>(`/orgs/${org.id}/scopes`, {
        method: "POST",
        body: type === "CLOUD_ACCOUNT" ? { type, value: `aws:${value.trim()}`, roleArn: roleArn.trim() } : { type, value },
      });
      setOpen(res.scope.id);
      setValue("");
      setRoleArn("");
    }, "Added. Follow the steps below to prove you own it.");
  }

  const field = "rounded-md border border-line bg-sheet px-3 py-2 outline-none focus:border-ink";
  return (
    <section className="flex max-w-3xl flex-col gap-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Ownership</h1>
        <p className="mt-2 text-muted">
          Each boundary is something you&apos;ve proven you control. Aegis never looks outside them, and each proof must be
          re-checked every 90 days.
        </p>
      </div>

      {manage && (
        <form onSubmit={add} className="flex flex-col gap-3 rounded-md border border-line bg-sheet p-4 sm:flex-row sm:flex-wrap sm:items-end">
          <label className="flex flex-col gap-1 text-sm font-medium">
            What do you own?
            <select value={type} onChange={(e) => setType(e.target.value as Scope["type"])} className={field}>
              <option value="DOMAIN">A domain</option>
              <option value="IP_RANGE">An IP address</option>
              <option value="CLOUD_ACCOUNT">An AWS account</option>
            </select>
          </label>
          <label className="flex flex-1 flex-col gap-1 text-sm font-medium">
            {type === "DOMAIN" ? "Domain" : type === "IP_RANGE" ? "IP address" : "AWS account ID"}
            <input
              required
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder={type === "DOMAIN" ? "example.com" : type === "IP_RANGE" ? "203.0.113.10" : "123456789012"}
              className={`${field} font-mono text-[14px]`}
            />
          </label>
          {type === "CLOUD_ACCOUNT" && (
            <label className="flex w-full flex-col gap-1 text-sm font-medium">
              Role ARN
              <input
                required
                value={roleArn}
                onChange={(e) => setRoleArn(e.target.value)}
                placeholder="arn:aws:iam::123456789012:role/AegisReadOnly"
                className={`${field} font-mono text-[14px]`}
              />
            </label>
          )}
          <button type="submit" className={btnPrimary}>
            Add boundary
          </button>
        </form>
      )}

      <ul className="flex flex-col gap-6">
        {scopes.map((s) => {
          const st = SCOPE_STATUS[s.status];
          const methods = Object.keys(s.verification ?? {});
          return (
            <li key={s.id} className="border-l-4 border-boundary pl-4">
              <div className="flex flex-wrap items-baseline gap-x-4 gap-y-2">
                <span className="font-mono text-base font-medium">{s.value}</span>
                <span className={`text-sm font-medium ${st.tone}`}>{st.label}</span>
                {s.status === "VERIFIED" && <span className="text-sm text-muted">until {fmtDate(s.expiresAt)}</span>}
                {s.status !== "REVOKED" && (
                  <button onClick={() => setOpen(open === s.id ? null : s.id)} className="text-sm text-muted underline underline-offset-4 hover:text-ink" aria-expanded={open === s.id}>
                    {open === s.id ? "Hide steps" : "How to prove it"}
                  </button>
                )}
                {manage && s.status !== "REVOKED" && (
                  <label className="ml-auto flex items-center gap-1.5 text-sm text-muted">
                    Importance
                    <select
                      value={s.criticality}
                      onChange={(e) => act(() => api(`/orgs/${org.id}/scopes/${s.id}/criticality`, { method: "POST", body: { criticality: e.target.value } }), `Set ${s.value} importance to ${e.target.value.toLowerCase()}.`)}
                      className="rounded border border-line bg-sheet px-1.5 py-0.5"
                      title="Scales the risk score of findings on this boundary"
                    >
                      <option value="LOW">Low</option>
                      <option value="MEDIUM">Normal</option>
                      <option value="HIGH">High</option>
                    </select>
                  </label>
                )}
              </div>
              {s.lastVerificationError && s.status !== "VERIFIED" && (
                <p className="mt-2 text-sm text-stop">Last check: {s.lastVerificationError}</p>
              )}
              {open === s.id && <Instructions scope={s} />}
              {manage && s.status !== "REVOKED" && (
                <div className="mt-3 flex flex-wrap gap-2">
                  {methods.map((m) => (
                    <button
                      key={m}
                      onClick={() =>
                        act(() => api(`/orgs/${org.id}/scopes/${s.id}/verify`, { method: "POST", body: { method: m } }), `Ownership of ${s.value} proven.`)
                      }
                      className={btnQuiet}
                    >
                      Check {METHOD_LABEL[m] ?? m}
                    </button>
                  ))}
                  <button
                    onClick={() => {
                      if (confirm(`Revoke ${s.value}? Its scans stop now and it can't be scanned again.`)) {
                        void act(() => api(`/orgs/${org.id}/scopes/${s.id}/revoke`, { method: "POST" }), `${s.value} revoked.`);
                      }
                    }}
                    className={`${btn} text-stop hover:bg-stop/10`}
                  >
                    Revoke
                  </button>
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}

// ── Scans ──────────────────────────────────────────────────────────

export function ScansView({ org, scans, assets, act }: { org: OrgSummary; scans: Scan[]; assets: Asset[]; act: Act }) {
  const byId = new Map(assets.map((a) => [a.id, a.address]));
  if (scans.length === 0) {
    return (
      <section className="max-w-xl">
        <h1 className="text-2xl font-semibold tracking-tight">No scans yet</h1>
        <p className="mt-3 text-muted">Run asset discovery from the Assets tab once a boundary is proven.</p>
      </section>
    );
  }
  return (
    <section>
      <h1 className="text-2xl font-semibold tracking-tight">Scans</h1>
      <div className="mt-4 overflow-x-auto">
        <table className="w-full min-w-[640px] border-collapse text-sm">
          <thead>
            <tr className="border-b border-line text-left text-muted">
              <th className="py-2 pr-4 font-medium">Target</th>
              <th className="py-2 pr-4 font-medium">Scan</th>
              <th className="py-2 pr-4 font-medium">Status</th>
              <th className="py-2 pr-4 font-medium">Requested</th>
              <th className="py-2 font-medium" />
            </tr>
          </thead>
          <tbody>
            {scans.map((s) => {
              const st = SCAN_STATUS[s.status];
              const active = s.status === "QUEUED" || s.status === "RUNNING" || s.status === "PENDING_APPROVAL";
              return (
                <tr key={s.id} className="border-b border-line/60">
                  <td className="py-2 pr-4 font-mono text-[13px]">{(s.assetId && byId.get(s.assetId)) ?? "—"}</td>
                  <td className="py-2 pr-4">{ENGINE_LABEL[s.engine]}</td>
                  <td className={`py-2 pr-4 font-medium ${st.tone}`}>{st.label}</td>
                  <td className="py-2 pr-4 whitespace-nowrap text-muted">{fmtTime(s.createdAt)}</td>
                  <td className="py-2 text-right whitespace-nowrap">
                    {s.status === "PENDING_APPROVAL" && can.approve(org.role) && (
                      <button
                        onClick={() => act(() => api(`/orgs/${org.id}/scans/${s.id}/approve`, { method: "POST" }), "Approved and queued.")}
                        className={`${btnQuiet} mr-2`}
                      >
                        Approve
                      </button>
                    )}
                    {active && can.runScans(org.role) && (
                      <button
                        onClick={() => act(() => api(`/orgs/${org.id}/scans/${s.id}/kill`, { method: "POST" }), "Scan stopped.")}
                        className={`${btn} text-stop hover:bg-stop/10`}
                      >
                        Stop
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

// ── Findings ───────────────────────────────────────────────────────

const SEVERITY_META: Record<Severity, { label: string; chip: string; order: number }> = {
  CRITICAL: { label: "Critical", chip: "bg-stop text-sheet", order: 4 },
  HIGH: { label: "High", chip: "bg-stop/15 text-stop", order: 3 },
  MEDIUM: { label: "Medium", chip: "bg-wait/15 text-wait", order: 2 },
  LOW: { label: "Low", chip: "bg-line text-ink", order: 1 },
  INFO: { label: "Info", chip: "bg-line/60 text-muted", order: 0 },
};
const FINDING_STATUS: Record<FindingStatus, string> = {
  OPEN: "Open",
  TRIAGED: "Triaged",
  FIXED: "Fixed",
  FALSE_POSITIVE: "Not a problem",
};
const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

function EvidenceList({ evidence }: { evidence: Record<string, unknown> | null }) {
  if (!evidence) return null;
  const entries = Object.entries(evidence).filter(([, v]) => v !== null && v !== undefined && v !== "");
  if (entries.length === 0) return null;
  return (
    <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
      {entries.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-muted">{k}</dt>
          <dd className="font-mono [overflow-wrap:anywhere]">{typeof v === "object" ? JSON.stringify(v) : String(v)}</dd>
        </div>
      ))}
    </dl>
  );
}

export function FindingsView({
  org,
  findings,
  summary,
  act,
}: {
  org: OrgSummary;
  findings: Finding[];
  summary: SeveritySummary;
  act: Act;
}) {
  const [open, setOpen] = useState<string | null>(null);
  const [hideResolved, setHideResolved] = useState(true);
  const shown = findings
    .filter((f) => !hideResolved || (f.status !== "FIXED" && f.status !== "FALSE_POSITIVE"))
    // Highest risk score first; findings without a score fall back to severity.
    .sort((a, b) => (b.riskScore ?? -1) - (a.riskScore ?? -1) || SEVERITY_META[b.severity].order - SEVERITY_META[a.severity].order);
  const total = SEVERITY_ORDER.reduce((n, s) => n + summary[s], 0);

  if (findings.length === 0) {
    return (
      <section className="max-w-xl">
        <h1 className="text-2xl font-semibold tracking-tight">No findings yet</h1>
        <p className="mt-3 text-muted">
          Run a TLS, Web or Ports check on an asset (Assets tab). What each check sees shows up here, worst first, with how to
          fix it.
        </p>
      </section>
    );
  }

  return (
    <section>
      <div className="flex flex-wrap items-baseline justify-between gap-4">
        <h1 className="text-2xl font-semibold tracking-tight">Findings</h1>
        <label className="flex items-center gap-2 text-sm text-muted">
          <input type="checkbox" checked={hideResolved} onChange={(e) => setHideResolved(e.target.checked)} />
          Hide fixed and dismissed
        </label>
      </div>

      {total > 0 && (
        <div className="mt-4 flex flex-wrap gap-2">
          {SEVERITY_ORDER.filter((s) => summary[s] > 0).map((s) => (
            <span key={s} className={`rounded px-2 py-1 text-sm font-medium ${SEVERITY_META[s].chip}`}>
              {summary[s]} {SEVERITY_META[s].label.toLowerCase()}
            </span>
          ))}
        </div>
      )}

      <ul className="mt-6 flex flex-col divide-y divide-line border-y border-line">
        {shown.map((f) => {
          const meta = SEVERITY_META[f.severity];
          const expanded = open === f.id;
          const resolved = f.status === "FIXED" || f.status === "FALSE_POSITIVE";
          return (
            <li key={f.id} className={resolved ? "opacity-60" : ""}>
              <button
                onClick={() => setOpen(expanded ? null : f.id)}
                aria-expanded={expanded}
                className="flex w-full items-baseline gap-3 py-3 text-left"
              >
                <span className="flex w-16 shrink-0 flex-col items-center gap-0.5">
                  <span className={`w-full rounded px-1.5 py-0.5 text-center text-xs font-semibold ${meta.chip}`}>{meta.label}</span>
                  {f.riskScore !== null && (
                    <span className="text-[11px] text-muted" title="Combined risk: CVSS × EPSS × asset importance">
                      risk {f.riskScore}
                    </span>
                  )}
                </span>
                <span className="flex-1">
                  <span className="font-medium">{f.title}</span>
                  {f.kevListed && (
                    <span className="ml-2 rounded bg-stop px-1.5 py-0.5 text-[11px] font-semibold text-sheet" title="On CISA's Known Exploited Vulnerabilities list — actively exploited in the wild">
                      Exploited
                    </span>
                  )}
                  <span className="ml-2 font-mono text-[13px] text-muted [overflow-wrap:anywhere]">{f.assetAddress}</span>
                </span>
                {f.status !== "OPEN" && <span className="shrink-0 text-xs text-muted">{FINDING_STATUS[f.status]}</span>}
              </button>
              {expanded && (
                <div className="pb-4 pl-[4.75rem] text-sm">
                  {f.remediation && <p className="max-w-2xl">{f.remediation}</p>}
                  {(f.cveRefs.length > 0 || f.epss !== null) && (
                    <p className="mt-2 text-muted">
                      {f.cveRefs.join(", ")}
                      {f.cvss !== null && ` · CVSS ${f.cvss}`}
                      {f.epss !== null && ` · ${Math.round(f.epss * 100)}% chance of exploitation in the next 30 days (EPSS)`}
                      {f.kevListed && ` · on CISA's Known Exploited list`}
                    </p>
                  )}
                  <EvidenceList evidence={f.evidence} />
                  <p className="mt-2 text-xs text-muted">
                    First seen {fmtDate(f.firstSeenAt)} · last seen {fmtDate(f.lastSeenAt)}
                  </p>
                  {can.triage(org.role) && (
                    <div className="mt-3 flex flex-wrap gap-2">
                      {(["TRIAGED", "FIXED", "FALSE_POSITIVE", "OPEN"] as FindingStatus[])
                        .filter((st) => st !== f.status)
                        .map((st) => (
                          <button
                            key={st}
                            onClick={() => act(() => api(`/orgs/${org.id}/findings/${f.id}/status`, { method: "POST", body: { status: st } }), `Marked "${f.title}" ${FINDING_STATUS[st].toLowerCase()}.`)}
                            className={btnQuiet}
                          >
                            Mark {FINDING_STATUS[st].toLowerCase()}
                          </button>
                        ))}
                    </div>
                  )}
                </div>
              )}
            </li>
          );
        })}
      </ul>
      {shown.length === 0 && <p className="mt-6 text-muted">Everything&apos;s been resolved. Uncheck the filter to see fixed items.</p>}
    </section>
  );
}
