import { createHmac, randomBytes } from "node:crypto";
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
