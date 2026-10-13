import { spawn } from "node:child_process";

/**
 * Runs an external tool (subfinder, httpx, ...) the safe way:
 * - argv array, never a shell, so hostnames can't inject commands;
 * - a minimal environment (no platform secrets leak into the tool);
 * - hard timeout, output cap, and abort on kill.
 */
export interface ToolRunOptions {
  bin: string;
  args: string[];
  /** Written to stdin, then stdin is closed. */
  input?: string;
  timeoutMs: number;
  maxOutputBytes?: number;
  signal?: AbortSignal;
  /**
   * Extra environment variables for this one run, merged over the minimal safe
   * set. For passing *ephemeral, caller-chosen* secrets (e.g. assumed-role AWS
   * credentials) to a tool — never the platform's own long-lived env.
   */
  extraEnv?: Record<string, string | undefined>;
}

export interface ToolRunResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  truncated: boolean;
}

export class ToolMissingError extends Error {
  constructor(public readonly bin: string) {
    super(`tool not installed: ${bin}`);
    this.name = "ToolMissingError";
  }
}

const SAFE_ENV_KEYS = ["PATH", "HOME", "TMPDIR", "TEMP", "TMP", "SystemRoot", "LANG"];

export function runTool(opts: ToolRunOptions): Promise<ToolRunResult> {
  const max = opts.maxOutputBytes ?? 20 * 1024 * 1024;
  const env: NodeJS.ProcessEnv = {};
  for (const k of SAFE_ENV_KEYS) if (process.env[k] !== undefined) env[k] = process.env[k];
  if (opts.extraEnv) for (const [k, v] of Object.entries(opts.extraEnv)) if (v !== undefined) env[k] = v;

  return new Promise((resolve, reject) => {
    if (opts.signal?.aborted) return reject(opts.signal.reason ?? new Error("aborted"));
    const child = spawn(opts.bin, opts.args, { shell: false, env, stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
    let stdout = "";
    let stderr = "";
    let size = 0;
    let truncated = false;
    let settled = false;

    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      opts.signal?.removeEventListener("abort", onAbort);
      fn();
    };
    const kill = () => {
      if (child.exitCode === null) child.kill("SIGKILL");
    };
    const timer = setTimeout(() => {
      kill();
      finish(() => reject(new Error(`${opts.bin} timed out after ${opts.timeoutMs}ms`)));
    }, opts.timeoutMs);
    const onAbort = () => {
      kill();
      finish(() => reject(opts.signal!.reason ?? new Error("aborted")));
    };
    opts.signal?.addEventListener("abort", onAbort, { once: true });

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      size += Buffer.byteLength(chunk);
      if (size > max) {
        truncated = true;
        kill();
        return;
      }
      stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
      if (stderr.length < 64 * 1024) stderr += chunk;
    });
    child.on("error", (err: NodeJS.ErrnoException) => {
      finish(() => reject(err.code === "ENOENT" ? new ToolMissingError(opts.bin) : err));
    });
    child.on("close", (code) => finish(() => resolve({ stdout, stderr, exitCode: code, truncated })));

    child.stdin.on("error", () => {}); // tool may exit before reading stdin
    child.stdin.end(opts.input ?? "");
  });
}
