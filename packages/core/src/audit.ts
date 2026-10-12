import type { Actor } from "./types.js";

/**
 * Append-only audit trail (CLAUDE.md rule 5).
 *
 * The helper exposes a single operation, `record`, and the sink contract has
 * no update or delete. The Postgres table also has a trigger that rejects
 * UPDATE/DELETE, so immutability holds even for code that bypasses this helper.
 */

export type AuditAction =
  | "auth.register"
  | "auth.login"
  | "auth.login_failed"
  | "auth.refresh"
  | "auth.refresh_reuse_detected"
  | "auth.logout"
  | "org.create"
  | "member.invite"
  | "member.join"
  | "scope.create"
  | "scope.verify"
  | "scope.verify_failed"
  | "scope.revoke"
  | "scan.requested"
  | "scan.approved"
  | "scan.started"
  | "scan.completed"
  | "scan.failed"
  | "scan.authorized"
  | "scan.needs_approval"
  | "scan.throttled"
  | "scan.rejected"
  | "finding.triaged"
  | "report.create"
  | "report.shared"
  | "scan.killed"
  | "killswitch.engaged"
  | "killswitch.released";

export interface AuditInput {
  action: AuditAction;
  actor: Actor;
  orgId?: string | null;
  scopeId?: string | null;
  scanId?: string | null;
  targetId?: string | null;
  ip?: string | null;
  userAgent?: string | null;
  payload?: Record<string, unknown> | null;
}

export interface AuditEvent {
  readonly id: string;
  readonly action: AuditAction;
  readonly actor: Readonly<Actor>;
  readonly orgId: string | null;
  readonly scopeId: string | null;
  readonly scanId: string | null;
  readonly targetId: string | null;
  readonly ip: string | null;
  readonly userAgent: string | null;
  readonly payload: Readonly<Record<string, unknown>> | null;
  readonly createdAt: Date;
}

/** Storage backend. Implementations must only ever insert. */
export interface AuditSink {
  append(event: AuditEvent): Promise<void>;
}

export interface AuditLogger {
  record(input: AuditInput): Promise<AuditEvent>;
}

/** Payload keys whose values must never be written to the audit log. */
const SENSITIVE_KEY = /pass(word)?|secret|token|authorization|cookie|api[-_]?key/i;

function redact(value: unknown, depth = 0): unknown {
  if (value === null || typeof value !== "object") return value;
  if (depth > 8) return "[TRUNCATED]";
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value)) {
    out[k] = SENSITIVE_KEY.test(k) ? "[REDACTED]" : redact(v, depth + 1);
  }
  return out;
}

function deepFreeze<T>(obj: T): T {
  if (obj && typeof obj === "object" && !Object.isFrozen(obj)) {
    Object.freeze(obj);
    for (const v of Object.values(obj)) deepFreeze(v);
  }
  return obj;
}

export function createAuditLogger(
  sink: AuditSink,
  opts: { now?: () => Date; newId?: () => string } = {},
): AuditLogger {
  const now = opts.now ?? (() => new Date());
  const newId = opts.newId ?? (() => crypto.randomUUID());

  return {
    async record(input) {
      if (!input.action) throw new Error("audit: action is required");
      const event: AuditEvent = deepFreeze({
        id: newId(),
        action: input.action,
        actor: { ...input.actor },
        orgId: input.orgId ?? null,
        scopeId: input.scopeId ?? null,
        scanId: input.scanId ?? null,
        targetId: input.targetId ?? null,
        ip: input.ip ?? null,
        userAgent: input.userAgent ?? null,
        payload: redact(input.payload ?? null) as Record<string, unknown> | null,
        createdAt: now(),
      });
      // Errors propagate: an action whose audit write fails must not be
      // reported as successful.
      await sink.append(event);
      return event;
    },
  };
}

/** In-memory sink for tests and local tooling. `events` returns a copy. */
export function createMemoryAuditSink(): AuditSink & { readonly events: readonly AuditEvent[] } {
  const events: AuditEvent[] = [];
  return {
    get events() {
      return events.slice();
    },
    async append(event) {
      events.push(event);
    },
  };
}
