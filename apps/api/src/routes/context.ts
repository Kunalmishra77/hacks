import type { FastifyRequest } from "fastify";

/** Request metadata recorded on every audit event. */
export function requestContext(req: FastifyRequest): { ip: string; userAgent: string | null } {
  const ua = req.headers["user-agent"];
  return { ip: req.ip, userAgent: typeof ua === "string" ? ua.slice(0, 512) : null };
}
