/**
 * Fixed-window rate limiter port. The API uses a Redis implementation so
 * limits hold across processes; tests use the in-memory one below.
 */
export interface RateLimitResult {
  allowed: boolean;
  /** Milliseconds until the window resets. 0 when allowed. */
  retryAfterMs: number;
}

export interface RateLimiter {
  /** Records one hit on `key` and reports whether it is within `limit` per `windowMs`. */
  hit(key: string, limit: number, windowMs: number): Promise<RateLimitResult>;
}

export function createMemoryRateLimiter(opts: { now?: () => number } = {}): RateLimiter {
  const now = opts.now ?? Date.now;
  const windows = new Map<string, { count: number; resetAt: number }>();
  return {
    async hit(key, limit, windowMs) {
      const t = now();
      let w = windows.get(key);
      if (!w || w.resetAt <= t) {
        w = { count: 0, resetAt: t + windowMs };
        windows.set(key, w);
      }
      w.count += 1;
      return w.count <= limit ? { allowed: true, retryAfterMs: 0 } : { allowed: false, retryAfterMs: w.resetAt - t };
    },
  };
}
