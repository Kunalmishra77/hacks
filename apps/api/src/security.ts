import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import argon2 from "argon2";
import { jwtVerify, SignJWT } from "jose";

// ── Passwords (argon2id, OWASP-recommended parameters) ──────────────

const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19_456, // KiB
  timeCost: 2,
  parallelism: 1,
} as const;

export function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, ARGON2_OPTIONS);
}

export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

// Verified against when the user doesn't exist, so a login attempt costs the
// same time whether or not the email is registered.
let dummyHash: Promise<string> | undefined;
export async function burnPasswordCheck(password: string): Promise<void> {
  dummyHash ??= hashPassword(randomBytes(16).toString("hex"));
  await verifyPassword(await dummyHash, password);
}

// ── Opaque tokens (refresh tokens, invite tokens) ───────────────────

/** 256-bit random token, URL-safe. Shown to the client once, never stored. */
export function newOpaqueToken(): string {
  return randomBytes(32).toString("base64url");
}

/**
 * Keyed hash used to store opaque tokens. With an HMAC (JWT_REFRESH_SECRET)
 * instead of a plain hash, a database leak alone doesn't let anyone check
 * guessed tokens against it.
 */
export function hashOpaqueToken(token: string, key: string): string {
  return createHmac("sha256", key).update(token).digest("hex");
}

// ── Signed, expiring download links (shareable report URLs) ─────────
// A stateless token "<id>.<expEpochSec>.<hmac>" so a report can be shared
// without a login, time-limited, and revocable only by expiry. No DB lookup
// to validate; the id is checked against the DB after the signature passes.

function b64urlHmac(data: string, key: string): string {
  return createHmac("sha256", key).update(data).digest("base64url");
}

export function signDownloadToken(id: string, expiresAtSec: number, key: string): string {
  const data = `${id}.${expiresAtSec}`;
  return `${data}.${b64urlHmac(data, key)}`;
}

/** Returns the id if the token is well-formed, unexpired and correctly signed; else null. */
export function verifyDownloadToken(token: string, key: string, nowSec = Math.floor(Date.now() / 1000)): string | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [id, expStr, sig] = parts as [string, string, string];
  const exp = Number(expStr);
  if (!/^[0-9a-f-]{36}$/.test(id) || !Number.isInteger(exp) || exp < nowSec) return null;
  const expected = b64urlHmac(`${id}.${exp}`, key);
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b) ? id : null;
}

// ── Access tokens (JWT, HS256) ──────────────────────────────────────

const AUDIENCE = "aegis";

export interface AccessTokenClaims {
  sub: string;
}

export async function signAccessToken(
  userId: string,
  opts: { secret: string; issuer: string; ttlSeconds: number },
): Promise<string> {
  return new SignJWT({ typ: "access" })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(userId)
    .setIssuer(opts.issuer)
    .setAudience(AUDIENCE)
    .setIssuedAt()
    .setExpirationTime(`${opts.ttlSeconds}s`)
    .sign(new TextEncoder().encode(opts.secret));
}

/** Returns claims, or null for any invalid/expired/foreign token. */
export async function verifyAccessToken(
  token: string,
  opts: { secret: string; issuer: string },
): Promise<AccessTokenClaims | null> {
  try {
    const { payload } = await jwtVerify(token, new TextEncoder().encode(opts.secret), {
      algorithms: ["HS256"],
      issuer: opts.issuer,
      audience: AUDIENCE,
    });
    if (payload.typ !== "access" || typeof payload.sub !== "string") return null;
    return { sub: payload.sub };
  } catch {
    return null;
  }
}
