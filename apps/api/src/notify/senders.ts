import type { Alert } from "@aegis/core";
import type { NotificationType } from "../store/types.js";
import { isPublicAddress } from "@aegis/core";
import { Resolver } from "node:dns/promises";
import { isIP } from "node:net";

// Delivers an Alert to one channel. Each sender is small and testable; the
// network ones take an injected fetch / transport. Webhook and WhatsApp URLs
// are customer-controlled, so they go through an SSRF check before any request.

export interface SenderChannel {
  type: NotificationType;
  target: string;
}

export interface Senders {
  send(channel: SenderChannel, alert: Alert): Promise<void>;
}

export interface SenderDeps {
  fetch?: typeof fetch;
  /** Sends an email; absent means email channels are unconfigured. */
  sendEmail?: (to: string, subject: string, text: string) => Promise<void>;
  /** WhatsApp Cloud API phone-number id + token; absent means WhatsApp is unconfigured. */
  whatsapp?: { phoneNumberId: string; token: string };
  resolve?: (host: string) => Promise<string[]>;
}

async function assertPublicUrl(raw: string, resolve: (host: string) => Promise<string[]>): Promise<URL> {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("invalid URL");
  }
  if (url.protocol !== "https:") throw new Error("webhook URL must be https");
  const host = url.hostname;
  const addrs = isIP(host) ? [host] : await resolve(host);
  if (addrs.length === 0 || !addrs.every(isPublicAddress)) throw new Error(`refusing to post to non-public host ${host}`);
  return url;
}

async function postJson(fetchFn: typeof fetch, url: URL, body: unknown): Promise<void> {
  const res = await fetchFn(url.toString(), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(10_000),
    redirect: "error",
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
}

function defaultResolve(): (host: string) => Promise<string[]> {
  const r = new Resolver({ timeout: 4000, tries: 2 });
  r.setServers(["1.1.1.1", "8.8.8.8"]);
  return async (host) => {
    const [v4, v6] = await Promise.all([r.resolve4(host).catch(() => []), r.resolve6(host).catch(() => [])]);
    return [...v4, ...v6];
  };
}

export function createSenders(deps: SenderDeps = {}): Senders {
  const fetchFn = deps.fetch ?? fetch;
  const resolve = deps.resolve ?? defaultResolve();

  return {
    async send(channel, alert) {
      switch (channel.type) {
        case "SLACK": {
          const url = await assertPublicUrl(channel.target, resolve);
          return postJson(fetchFn, url, alert.slack);
        }
        case "WEBHOOK": {
          const url = await assertPublicUrl(channel.target, resolve);
          return postJson(fetchFn, url, alert.webhook);
        }
        case "EMAIL": {
          if (!deps.sendEmail) throw new Error("email is not configured (set SMTP_URL)");
          return deps.sendEmail(channel.target, alert.subject, alert.text);
        }
        case "WHATSAPP": {
          if (!deps.whatsapp) throw new Error("WhatsApp is not configured");
          const url = new URL(`https://graph.facebook.com/v21.0/${deps.whatsapp.phoneNumberId}/messages`);
          const res = await fetchFn(url.toString(), {
            method: "POST",
            headers: { authorization: `Bearer ${deps.whatsapp.token}`, "content-type": "application/json" },
            body: JSON.stringify({ messaging_product: "whatsapp", to: channel.target, type: "text", text: { body: alert.text.slice(0, 4000) } }),
            signal: AbortSignal.timeout(10_000),
          });
          if (!res.ok) throw new Error(`WhatsApp HTTP ${res.status}`);
          return;
        }
      }
    },
  };
}
