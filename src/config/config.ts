import { readFileSync, existsSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import { DEFAULT_CONFIG, type AuliteConfig } from "./types.js";
import { logger } from "../utils/logger.js";

const CONFIG_PATHS = ["aulite.config.yml", "aulite.config.yaml"];

function deepMerge(target: Record<string, unknown>, source: Record<string, unknown>): Record<string, unknown> {
  const result = { ...target };
  for (const key of Object.keys(source)) {
    if (
      source[key] &&
      typeof source[key] === "object" &&
      !Array.isArray(source[key]) &&
      target[key] &&
      typeof target[key] === "object"
    ) {
      result[key] = deepMerge(target[key] as Record<string, unknown>, source[key] as Record<string, unknown>);
    } else {
      result[key] = source[key];
    }
  }
  return result;
}

function interpolateEnvVars(obj: unknown): unknown {
  if (typeof obj === "string") {
    return obj.replace(/\$\{(\w+)\}/g, (_, key) => process.env[key] ?? "");
  }
  if (Array.isArray(obj)) {
    return obj.map(interpolateEnvVars);
  }
  if (obj !== null && typeof obj === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = interpolateEnvVars(value);
    }
    return result;
  }
  return obj;
}

export function loadConfig(): AuliteConfig {
  let raw: Record<string, unknown> = {};

  for (const path of CONFIG_PATHS) {
    if (existsSync(path)) {
      const content = readFileSync(path, "utf-8");
      raw = parseYaml(content) as Record<string, unknown>;
      logger.debug("Config loaded", { path });
      break;
    }
  }

  const interpolated = interpolateEnvVars(raw) as Record<string, unknown>;
  const config = deepMerge(DEFAULT_CONFIG as unknown as Record<string, unknown>, interpolated) as unknown as AuliteConfig;

  if (process.env.OPENAI_API_KEY) {
    config.provider.openai = {
      baseUrl: config.provider.openai?.baseUrl ?? "https://api.openai.com",
      apiKey: process.env.OPENAI_API_KEY,
    };
  }
  if (process.env.ANTHROPIC_API_KEY) {
    config.provider.anthropic = {
      baseUrl: config.provider.anthropic?.baseUrl ?? "https://api.anthropic.com",
      apiKey: process.env.ANTHROPIC_API_KEY,
    };
  }

  if (process.env.AULITE_PORT) {
    config.server.port = parseInt(process.env.AULITE_PORT, 10);
  }
  if (process.env.AULITE_HOST) {
    config.server.host = process.env.AULITE_HOST;
  }
  if (process.env.AULITE_DOMAINS) {
    config.analysis.domains = process.env.AULITE_DOMAINS.split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }
  if (process.env.AULITE_RULES_DIR) {
    config.analysis.rulesDir = process.env.AULITE_RULES_DIR;
  }
  if (process.env.AULITE_LICENSE_KEY) {
    config.license = process.env.AULITE_LICENSE_KEY;
  }
  if (process.env.AULITE_API_KEYS) {
    config.auth = {
      apiKeys: process.env.AULITE_API_KEYS.split(",").map((s) => s.trim()).filter(Boolean),
    };
  }
  if (process.env.AULITE_RATE_LIMIT) {
    config.rateLimit = {
      requestsPerMinute: parseInt(process.env.AULITE_RATE_LIMIT, 10),
    };
  }
  if (config.anchor) {
    if (process.env.AULITE_ANCHOR_ENABLED) {
      config.anchor.enabled = process.env.AULITE_ANCHOR_ENABLED === "true";
    }
    if (process.env.AULITE_ANCHOR_INTERVAL) {
      config.anchor.intervalMinutes = parseInt(process.env.AULITE_ANCHOR_INTERVAL, 10);
    }
    if (process.env.AULITE_REKOR_URL) {
      config.anchor.rekorUrl = process.env.AULITE_REKOR_URL;
    }
    if (process.env.AULITE_SIGNING_KEY_PATH) {
      config.anchor.keyPath = process.env.AULITE_SIGNING_KEY_PATH;
    }
  }
  if (process.env.AZURE_OPENAI_API_KEY && process.env.AZURE_OPENAI_ENDPOINT) {
    config.provider.azure = {
      baseUrl: process.env.AZURE_OPENAI_ENDPOINT,
      apiKey: process.env.AZURE_OPENAI_API_KEY,
      deploymentId: process.env.AZURE_OPENAI_DEPLOYMENT ?? "gpt-4",
      apiVersion: process.env.AZURE_OPENAI_API_VERSION,
    };
  }

  const dp = config.provider.default;
  if (!config.provider[dp]) {
    throw new Error(`Default provider "${dp}" is not configured. Set ${dp.toUpperCase()}_API_KEY in .env`);
  }

  logger.debug("Provider configured", { provider: dp });
  return config;
}
