import { buildAlert, selectAlertable, type AlertFinding } from "@aegis/core";
import type { Senders } from "./senders.js";
import type { Store } from "../store/types.js";

// After a scan's findings are enriched, alert on anything new and notable.
// Advisory and best-effort: a failing channel is recorded and skipped, never
// fatal to the scan.

export interface DispatchDeps {
  store: Store;
  senders: Senders;
  dashboardUrl?: string;
  log?: (msg: string, data?: Record<string, unknown>) => void;
}

export interface DispatchResult {
  newFindings: number;
  channelsNotified: number;
  channelsFailed: number;
}

export async function dispatchScanAlerts(
  deps: DispatchDeps,
  input: { orgId: string; scanId: string; scopeLabel: string; since: Date },
): Promise<DispatchResult> {
  const log = deps.log ?? (() => {});
  const result: DispatchResult = { newFindings: 0, channelsNotified: 0, channelsFailed: 0 };

  const [channels, org, newFindings] = await Promise.all([
    deps.store.channels.enabledForOrg(input.orgId),
    deps.store.orgs.findById(input.orgId),
    deps.store.findings.newForScan(input.scanId, input.since),
  ]);
  result.newFindings = newFindings.length;
  if (channels.length === 0 || newFindings.length === 0 || !org) return result;

  const asAlert: AlertFinding[] = newFindings.map((f) => ({
    title: f.title,
    severity: f.severity,
    riskScore: f.riskScore,
    kevListed: f.kevListed,
    assetAddress: f.assetAddress,
  }));

  for (const channel of channels) {
    const selected = selectAlertable(asAlert, { minSeverity: channel.minSeverity, kevAlways: channel.kevAlways });
    if (selected.length === 0) continue;
    const alert = buildAlert({ orgName: org.name, scopeLabel: input.scopeLabel, findings: selected, dashboardUrl: deps.dashboardUrl });
    try {
      await deps.senders.send({ type: channel.type, target: channel.target }, alert);
      await deps.store.channels.recordResult(channel.id, new Date(), null);
      result.channelsNotified++;
    } catch (e) {
      await deps.store.channels.recordResult(channel.id, new Date(), (e as Error).message.slice(0, 300));
      result.channelsFailed++;
      log("alert delivery failed", { channelId: channel.id, type: channel.type, error: (e as Error).message });
    }
  }
  return result;
}
