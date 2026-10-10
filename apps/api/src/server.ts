import { prisma } from "@aegis/db";
import { buildApp } from "./app.js";
import { loadConfig } from "./config.js";
import { createPrismaStore } from "./store/prisma.js";

const config = loadConfig();
const app = await buildApp({ config, store: createPrismaStore(prisma), logger: true });

const shutdown = async (signal: string) => {
  app.log.info({ signal }, "shutting down");
  await app.close();
  await prisma.$disconnect();
  process.exit(0);
};
process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));

await app.listen({ host: config.host, port: config.port });
