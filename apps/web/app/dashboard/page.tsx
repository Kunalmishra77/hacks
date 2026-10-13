"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  api,
  ApiError,
  logout,
  refreshSession,
  type Asset,
  type Finding,
  type OrgSummary,
  type Scan,
  type Scope,
  type SeveritySummary,
  type Report,
  type Schedule,
  type Channel,
} from "@/lib/api";
import { AssetsView, FindingsView, KillSwitch, MonitoringView, ReportsView, ScansView, ScopesView } from "./views";

type Tab = "assets" | "findings" | "reports" | "scopes" | "scans" | "monitoring";
const TABS: { id: Tab; label: string }[] = [
  { id: "assets", label: "Assets" },
  { id: "findings", label: "Findings" },
  { id: "reports", label: "Reports" },
  { id: "monitoring", label: "Monitoring" },
  { id: "scopes", label: "Ownership" },
  { id: "scans", label: "Scans" },
];

const EMPTY_SUMMARY: SeveritySummary = { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };

const ACTIVE = new Set(["QUEUED", "RUNNING", "PENDING_APPROVAL"]);

export default function Dashboard() {
  const router = useRouter();
  const [orgs, setOrgs] = useState<OrgSummary[] | null>(null);
  const [orgId, setOrgId] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("assets");
  const [killSwitch, setKillSwitch] = useState(false);
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [summary, setSummary] = useState<SeveritySummary>(EMPTY_SUMMARY);
  const [reports, setReports] = useState<Report[]>([]);
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [channels, setChannels] = useState<Channel[]>([]);
  const [notice, setNotice] = useState<{ kind: "ok" | "error"; text: string } | null>(null);

  const org = useMemo(() => orgs?.find((o) => o.id === orgId) ?? null, [orgs, orgId]);

  // Session: the access token is in memory, so a reload refreshes it from the cookie.
  useEffect(() => {
    (async () => {
      try {
        const res = await api<{ orgs: OrgSummary[] }>("/orgs");
        setOrgs(res.orgs);
        setOrgId(res.orgs[0]?.id ?? null);
      } catch {
        if (!(await refreshSession())) router.replace("/login");
      }
    })();
  }, [router]);

  const reload = useCallback(async () => {
    if (!orgId) return;
    try {
      const [o, sc, as, sn, fn, rp, sch, ch] = await Promise.all([
        api<{ org: { killSwitchEngaged: boolean } }>(`/orgs/${orgId}`),
        api<{ scopes: Scope[] }>(`/orgs/${orgId}/scopes`),
        api<{ assets: Asset[] }>(`/orgs/${orgId}/assets`),
        api<{ scans: Scan[] }>(`/orgs/${orgId}/scans`),
        api<{ findings: Finding[]; summary: SeveritySummary }>(`/orgs/${orgId}/findings`),
        api<{ reports: Report[] }>(`/orgs/${orgId}/reports`),
        api<{ schedules: Schedule[] }>(`/orgs/${orgId}/schedules`),
        api<{ channels: Channel[] }>(`/orgs/${orgId}/channels`),
      ]);
      setKillSwitch(o.org.killSwitchEngaged);
      setScopes(sc.scopes);
      setAssets(as.assets);
      setScans(sn.scans);
      setFindings(fn.findings);
      setSummary(fn.summary);
      setReports(rp.reports);
      setSchedules(sch.schedules);
      setChannels(ch.channels);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) router.replace("/login");
    }
  }, [orgId, router]);

  useEffect(() => {
    void reload();
  }, [reload]);

  // While anything is in flight, keep the picture current.
  const busy = scans.some((s) => ACTIVE.has(s.status));
  useEffect(() => {
    if (!busy) return;
    const t = setInterval(() => void reload(), 5000);
    return () => clearInterval(t);
  }, [busy, reload]);

  /** Runs an action, shows its outcome, and refreshes. */
  const act = useCallback(
    async (fn: () => Promise<unknown>, ok: string) => {
      try {
        await fn();
        setNotice({ kind: "ok", text: ok });
      } catch (e) {
        setNotice({ kind: "error", text: describeError(e) });
      }
      await reload();
    },
    [reload],
  );

  if (!orgs) return <p className="p-8 text-muted">Loading…</p>;
  if (!org) {
    return (
      <main className="mx-auto max-w-lg p-8">
        <p>You&apos;re not in an organization yet. Ask an admin for an invite, or create an account with an organization.</p>
      </main>
    );
  }

  return (
    <div className="min-h-screen">
      <header className="border-b border-line bg-sheet">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-6 gap-y-3 px-4 py-3 sm:px-6">
          <span className="text-lg font-semibold tracking-tight">Aegis</span>
          {orgs.length > 1 ? (
            <select value={org.id} onChange={(e) => setOrgId(e.target.value)} className="rounded border border-line bg-sheet px-2 py-1 text-sm">
              {orgs.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.name}
                </option>
              ))}
            </select>
          ) : (
            <span className="text-sm text-muted">{org.name}</span>
          )}
          <nav className="flex gap-1" aria-label="Sections">
            {TABS.map((t) => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                aria-current={tab === t.id ? "page" : undefined}
                className={`rounded px-3 py-1.5 text-sm font-medium ${tab === t.id ? "bg-ink text-sheet" : "text-muted hover:text-ink"}`}
              >
                {t.label}
                {t.id === "findings" && summary.HIGH + summary.CRITICAL > 0 && (
                  <span className="ml-1.5 rounded-full bg-stop px-1.5 text-xs font-semibold text-sheet">{summary.HIGH + summary.CRITICAL}</span>
                )}
              </button>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-4">
            <KillSwitch
              engaged={killSwitch}
              role={org.role}
              onChange={(engaged) =>
                act(
                  () => api(`/orgs/${org.id}/kill-switch`, { method: "POST", body: { engaged } }),
                  engaged ? "All scans stopped. New scans are blocked until an admin allows them again." : "Scans are allowed again.",
                )
              }
            />
            <button
              onClick={async () => {
                await logout();
                router.replace("/login");
              }}
              className="text-sm text-muted hover:text-ink"
            >
              Sign out
            </button>
          </div>
        </div>
      </header>

      {notice && (
        <div role="status" className={`border-b px-4 py-2 text-sm sm:px-6 ${notice.kind === "ok" ? "border-ok/30 bg-ok/10" : "border-stop/30 bg-stop/10"}`}>
          <div className="mx-auto flex max-w-6xl items-start justify-between gap-4">
            <span>{notice.text}</span>
            <button onClick={() => setNotice(null)} className="text-muted hover:text-ink" aria-label="Dismiss">
              ✕
            </button>
          </div>
        </div>
      )}

      <main className="mx-auto max-w-6xl px-4 py-8 sm:px-6">
        {tab === "assets" && (
          <AssetsView org={org} scopes={scopes} assets={assets} scans={scans} killSwitch={killSwitch} findings={findings} act={act} onGoToScopes={() => setTab("scopes")} />
        )}
        {tab === "findings" && <FindingsView org={org} findings={findings} summary={summary} act={act} />}
        {tab === "reports" && <ReportsView org={org} reports={reports} scopes={scopes} act={act} />}
        {tab === "monitoring" && <MonitoringView org={org} schedules={schedules} channels={channels} scopes={scopes} act={act} />}
        {tab === "scopes" && <ScopesView org={org} scopes={scopes} act={act} />}
        {tab === "scans" && <ScansView org={org} scans={scans} assets={assets} act={act} />}
      </main>
    </div>
  );
}

const REASONS: Record<string, string> = {
  SCOPE_NOT_VERIFIED: "Prove you own this first (Ownership tab).",
  SCOPE_EXPIRED: "Ownership proof expired. Check ownership again to continue.",
  SCOPE_REVOKED: "This boundary was revoked.",
  ENGINE_NOT_ALLOWED: "That kind of scan isn't allowed for this boundary.",
  KILL_SWITCH_ENGAGED: "Scans are stopped for your organization.",
  TARGET_OUTSIDE_SCOPE: "That target is outside the proven boundary.",
  SCOPE_RATE_LIMIT: "Too many scans on this boundary right now. Try again in a minute.",
  ORG_CONCURRENCY_LIMIT: "Your organization is already running the maximum number of scans.",
};

function describeError(e: unknown): string {
  if (e instanceof ApiError) {
    const reason = typeof e.body.reason === "string" ? e.body.reason : null;
    if (reason && REASONS[reason]) return REASONS[reason];
    if (reason) return reason;
    if (e.status === 403) return "Your role can't do that.";
    if (e.status === 503) return "The scan queue is unreachable. The scan was marked failed.";
    return e.message;
  }
  return "Can't reach the Aegis API.";
}
