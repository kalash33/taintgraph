import { accounts, getProject, loadFindings, simulateWorm, summary, teams } from "./analysis.ts";
import { fixPlan } from "./fix.ts";
import { COMPROMISE, type InsightsView } from "./types.ts";

// The dashboard strip: the headline result of each graph technique for one project, in one request.
// Worm simulation, community detection and the fix plan take seconds on a small host. The result only changes with a
// new scan or a new verdict, so it is cached per scan and per set of finding statuses.
const cache = new Map<string, Promise<InsightsView>>();

export async function insights(org: string, projectId: string): Promise<InsightsView> {
  const p = await getProject(org, projectId);
  const statuses = (await loadFindings(org, p)).map((f) => f.id + f.status).join(",");
  const key = `${org}|${p.id}|${p.scanId}|${statuses}`;
  if (!cache.has(key)) {
    if (cache.size > 200) cache.delete(cache.keys().next().value!);
    cache.set(key, compute(org, projectId).catch((e) => (cache.delete(key), Promise.reject(e))));
  }
  return cache.get(key)!;
}

async function compute(org: string, projectId: string): Promise<InsightsView> {
  const p = await getProject(org, projectId);
  const [s, findings, top, t, plan] = await Promise.all([summary(org, projectId), loadFindings(org, p), accounts(org, p, 1), teams(org, p, 1), fixPlan(org, projectId)]);
  const bad = findings.filter((f) => COMPROMISE.includes(f.signal) && (f.status === "open" || f.status === "confirmed"));
  const deepest = [...bad].sort((a, b) => b.path.length - a.path.length)[0];
  const worm = top[0] ? await simulateWorm(org, p, top[0].login, 4).catch(() => null) : null;
  return {
    versions: s.counts.packages,
    edges: s.counts.edges,
    accounts: s.counts.accounts,
    compromised: new Set(bad.map((f) => f.versionKey)).size,
    deepest: deepest ? { name: deepest.name, version: deepest.version, hops: Math.max(1, deepest.path.length - 1), via: deepest.path.slice(1, -1).map((k) => k.replace(/^(npm|pypi)\//, "")).slice(0, 4) } : null,
    topAccount: top[0] ? { login: top[0].login, versions: top[0].versions, share: top[0].share, flagged: top[0].flagged } : null,
    worm: worm ? { start: worm.start, waves: worm.waves.length, poisonedShare: worm.poisonedShare, accounts: worm.compromisedAccounts } : null,
    topTeam: t.teams[0] ? { accounts: t.teams[0].accounts.slice(0, 3), size: t.teams[0].accounts.length, share: t.teams[0].share, flagged: t.teams[0].flagged } : null,
    network: t.network,
    fixes: plan.items.filter((i) => i.to || i.action === "remove").length,
    incident: plan.incident.length > 0,
  };
}
