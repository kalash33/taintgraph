import { after, describe, test } from "node:test";
import assert from "node:assert/strict";
import { close, falkor, orgGraph, ping } from "../src/db.ts";
import { loadCases, runCase } from "../src/benchmark.ts";

// Every real incident in benchmark/cases.json must be called compromised; no clean control may be.
const ORG = `incidents-${Date.now().toString(36)}`;
const up = await ping();

describe("real-world incidents", { skip: up ? false : "FalkorDB is not running on FALKORDB_URL", timeout: 600_000 }, () => {
  after(async () => {
    await (await falkor()).selectGraph(orgGraph(ORG)).delete().catch(() => {});
    await close();
  });
  for (const c of loadCases())
    test(`${c.expect === "clean" ? "clean control" : c.date} ${c.name}@${c.version}`, async () => {
      const r = await runCase(ORG, c);
      assert.ok(r.pass, `${c.id}: expected ${c.expect}, got ${r.verdict} (${r.signals.join(", ") || "no signals"})`);
    });
});
