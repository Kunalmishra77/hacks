import { PrismaClient } from "@prisma/client";

export * from "@prisma/client";

const globalForPrisma = globalThis as unknown as { __aegisPrisma?: PrismaClient };

/**
 * Process-wide Prisma client. Reused across hot reloads in development so we
 * don't exhaust Postgres connections.
 */
export const prisma: PrismaClient =
  globalForPrisma.__aegisPrisma ?? new PrismaClient();

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.__aegisPrisma = prisma;
}
