import "dotenv/config";
import { readFileSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { serve } from "@hono/node-server";
import { loadConfig } from "./config/config.js";
import { initDatabase } from "./logging/schema.js";
import { AuditLog } from "./logging/audit-log.js";
import { createServer } from "./proxy/server.js";
import { loadRulePacks } from "./rules/loader.js";
import { resolveEntitlements } from "./license.js";
import { Anchorer, loadOrCreateSigningKey } from "./logging/anchor.js";
import { printBanner, logger } from "./utils/logger.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

function readVersion(): string {
  const candidates = [resolve(__dirname, "../package.json"), resolve(process.cwd(), "package.json")];
  const pkgPath = candidates.find(existsSync);
  if (!pkgPath) return "0.0.0";
  return JSON.parse(readFileSync(pkgPath, "utf-8")).version;
}

function main(): void {
  const config = loadConfig();
  const entitlements = resolveEntitlements(config.license);
  const version = readVersion();
  const db = initDatabase(config.logging.database);
  const auditLog = new AuditLog(db);
  const app = createServer(config, auditLog, version);

  const { rules } = loadRulePacks(config.analysis.domains, config.analysis.rulesDir);

  if (config.anchor?.enabled) {
    const signingKey = loadOrCreateSigningKey(config.anchor.keyPath);
    const anchorer = new Anchorer(db, auditLog, signingKey, { rekorUrl: config.anchor.rekorUrl });
    anchorer.start(config.anchor.intervalMinutes * 60_000);
    logger.info("Audit anchoring enabled", {
      rekor: config.anchor.rekorUrl,
      intervalMinutes: config.anchor.intervalMinutes,
    });
  }

  const hasDashboard = [
    resolve(__dirname, "../dashboard/dist/index.html"),
    resolve(__dirname, "dashboard/index.html"),
    resolve(process.cwd(), "dashboard/dist/index.html"),
  ].some(existsSync);

  serve({ fetch: app.fetch, port: config.server.port }, () => {
    printBanner({
      version,
      port: config.server.port,
      host: config.server.host,
      provider: config.provider.default,
      mode: config.analysis.mode,
      domains: config.analysis.domains,
      rulesLoaded: rules.length,
      plan: entitlements.plan,
      auth: !!config.auth?.apiKeys?.length,
      rateLimit: config.rateLimit?.requestsPerMinute,
      dashboard: hasDashboard,
    });
  });

  const shutdown = () => {
    logger.info("Shutting down...");
    db.close();
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main();
