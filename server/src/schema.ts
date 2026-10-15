import { orgGraph, redis, run } from "./db.ts";

const RANGE = [
  ["Project", "id"],
  ["Scan", "id"],
  ["Version", "key"],
  ["Version", "name"],
  ["Package", "key"],
  ["Account", "key"],
  ["Account", "login"],
  ["Advisory", "id"],
  ["Finding", "id"],
  ["Finding", "project_id"],
  ["Rule", "id"],
  ["Investigation", "id"],
  ["Task", "status"],
  ["McpServer", "key"],
];
const UNIQUE = [
  ["Version", "key"],
  ["Package", "key"],
  ["Account", "key"],
  ["Advisory", "id"],
  ["Project", "id"],
];

const done = new Set<string>();

/** Indexes, a full-text index on advisory summaries, and unique constraints. Idempotent. */
export async function ensureSchema(org: string) {
  if (done.has(org)) return;
  const statements = [...RANGE.map(([l, p]) => `CREATE INDEX FOR (n:${l}) ON (n.${p})`), "CREATE FULLTEXT INDEX FOR (a:Advisory) ON (a.summary)"];
  for (const s of statements) {
    try {
      await run(org, s);
    } catch (e: any) {
      if (!/already/i.test(e.message)) console.warn("[schema]", s, e.message);
    }
  }
  const r = await redis();
  for (const [label, prop] of UNIQUE) {
    try {
      await r.sendCommand(["GRAPH.CONSTRAINT", "CREATE", orgGraph(org), "UNIQUE", "NODE", label, "PROPERTIES", "1", prop]);
    } catch (e: any) {
      if (!/already/i.test(e.message)) console.warn("[schema] constraint", label, prop, e.message);
    }
  }
  done.add(org);
}
