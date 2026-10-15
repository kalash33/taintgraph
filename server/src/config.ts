import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

// Load ../.env without extra dependencies (real environment variables win).
const envFile = join(ROOT, ".env");
if (existsSync(envFile)) {
  for (const line of readFileSync(envFile, "utf8").split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^["']|["']$/g, "");
  }
}

export const config = {
  falkordbUrl: process.env.FALKORDB_URL || "redis://localhost:6380",
  port: Number(process.env.PORT || 8787),
  defaultOrg: "demo",
  concurrency: 24,
  userAgent: "taintgraph-supply-chain/1.0 (graph hacks 2026)",
  trustProxy: process.env.TRUST_PROXY === "1",
};

export const paths = {
  queries: join(ROOT, "queries"),
  fixtures: join(ROOT, "fixtures"),
  web: join(ROOT, "web", "dist"),
};
