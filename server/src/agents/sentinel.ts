import pLimit from "p-limit";
import { read, redis, run } from "../db.ts";
import { Q } from "../queries.ts";
import { getProject, projectTree, triage } from "../analysis.ts";
import { classifyAdvisory, osvBatch, osvVuln } from "../ingest/feeds.ts";
import type { Ecosystem, SentinelResult } from "../types.ts";
import { createTask } from "./tasks.ts";

// The Sentinel retro-hunts: it re-checks every version any project in the workspace has ever installed against
// OSV.dev (bypassing the cache), links new advisories into the graph, and re-triages the projects they reach.
// A malware advisory published today finds the app that installed the package last month.


const running = new Set<string>();

export async function runSentinel(org: string): Promise<SentinelResult> {
  // One run per workspace at a time, across processes too.
  if (running.has(org)) throw Object.assign(new Error("The Sentinel is already running for this workspace."), { statusCode: 409 });
  const lock = `tg:lock:sentinel:${org}`;
  const r = await redis();
  const token = Math.random().toString(36).slice(2);
  if ((await r.set(lock, token, { NX: true, EX: 1800 })) !== "OK") throw Object.assign(new Error("The Sentinel is already running for this workspace."), { statusCode: 409 });
  running.add(org);
  try {
    return await hunt(org);
  } finally {
    running.delete(org);
    if ((await r.get(lock).catch(() => null)) === token) await r.del(lock).catch(() => {});
  }
}

async function hunt(org: string): Promise<SentinelResult> {
  const [versions, known] = await Promise.all([read(org, Q("observed_versions")), read(org, Q("advisories_known"))]);
  if (!versions.length) return { checked: 0, newAdvisories: 0, hits: [] };
  const had = new Map(known.map((k) => [k.key as string, new Set(k.ids as string[])]));
  const ids = await osvBatch(
    versions.map((v) => ({ name: v.name, version: v.version, ecosystem: v.ecosystem as Ecosystem })),
    true,
  );
  const fresh = new Set<string>();
  versions.forEach((v, i) => (ids[i] ?? []).forEach((id) => had.get(v.key)?.has(id) || fresh.add(id)));
  const limit = pLimit(16);
  const docs = new Map((await Promise.all([...fresh].map((id) => limit(async () => [id, await osvVuln(id).catch(() => null)] as const)))).filter(([, d]) => d));
  const rows: any[] = [];
  versions.forEach((v, i) => {
    for (const id of ids[i] ?? []) {
      if (had.get(v.key)?.has(id)) continue;
      const doc = docs.get(id);
      const c = doc && classifyAdvisory(doc, v.name, v.version);
      if (c) rows.push({ ...c, version: v.key });
    }
  });
  if (!rows.length) return { checked: versions.length, newAdvisories: 0, hits: [] };
  for (let i = 0; i < rows.length; i += 500) await run(org, Q("advisories_upsert"), { rows: rows.slice(i, i + 500) });

  const hits: SentinelResult["hits"] = [];
  const touched = new Set<string>();
  for (const row of rows)
    for (const p of await read(org, Q("projects_with_version"), { key: row.version })) {
      hits.push({ projectId: p.id, projectName: p.name, versionKey: row.version, advisoryId: row.id });
      touched.add(p.id);
    }
  // Re-triage each affected project on its latest scan and hand it to the Analyst again.
  for (const id of touched) {
    const p = await getProject(org, id);
    await triage(org, p, await projectTree(org, p));
    await createTask(org, id, "analyze", "analyst", { reason: "sentinel", advisories: [...new Set(hits.filter((h) => h.projectId === id).map((h) => h.advisoryId))] });
  }
  return { checked: versions.length, newAdvisories: new Set(rows.map((r) => r.id)).size, hits };
}
