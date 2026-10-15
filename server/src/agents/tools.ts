import { read } from "../db.ts";
import { Q, shown } from "../queries.ts";
import { accounts, loadFindings, pathTo, projectTree, short, simulateWorm, untrusted, verdictOf, type ProjectRef, type Tree } from "../analysis.ts";
import { editDistance } from "../ingest/heuristics.ts";
import { compareVersions } from "../ingest/feeds.ts";
import { COMPROMISE, type Evidence, type Outcome } from "../types.ts";
import type { ToolSpec } from "./llm.ts";

// The Analyst's tools. Each one is a fixed, human-written, parameterized Cypher query run with GRAPH.RO_QUERY:
// the model picks a tool and fills in names, it never writes Cypher. Names are resolved against the graph first,
// and every result says what kind of answer it is (answered / not_in_graph / unknown_name / from_memory).

export interface Ctx {
  org: string;
  project: ProjectRef;
  tree: () => Promise<Tree>;
}
export interface ToolResult {
  outcome: Outcome;
  summary: string; // plain-language result, names included
  data: unknown; // compact rows for the model
  query: string; // the .cypher file that ran (shown in the UI)
  evidence: Evidence;
}
export interface Tool {
  spec: ToolSpec;
  label: string;
  run(ctx: Ctx, args: Record<string, unknown>): Promise<ToolResult>;
}

export function context(org: string, project: ProjectRef): Ctx {
  let tree: Promise<Tree> | null = null;
  return { org, project, tree: () => (tree ??= projectTree(org, project)) };
}

const root = (c: Ctx) => `project/${c.project.id}`;
const label = (k: string) => (k.startsWith("project/") ? "your project" : short(k));
const route = (path: string[]) => path.map(label).join(" → ");
const ev = (nodes: string[] = [], edges: Evidence["edges"] = []): Evidence => ({ nodes: [...new Set(nodes)], edges });
const pathEdges = (path: string[]): Evidence["edges"] => path.slice(1).map((k, i) => [path[i], k, "DEPENDS_ON"]);
const str = (v: unknown, max = 200) => (typeof v === "string" ? v.trim().slice(0, max) : typeof v === "number" ? String(v) : "");
const merge = (...e: Evidence[]): Evidence => ev(e.flatMap((x) => x.nodes), [...new Map(e.flatMap((x) => x.edges).map((x) => [x.join("|"), x])).values()]);

/** "chalk@5.6.1", "npm/chalk@5.6.1", "`chalk`" -> { name, version } */
export function splitName(raw: string): { name: string; version?: string } {
  const s = raw.trim().replace(/^[`'"]+|[`'".,?!]+$/g, "").replace(/^(npm|pypi)\//i, "");
  const at = s.indexOf("@", 1);
  return at > 0 ? { name: s.slice(0, at), version: s.slice(at + 1) || undefined } : { name: s };
}

/** Closest package names in the project, for "did you mean". */
async function suggest(c: Ctx, name: string): Promise<string[]> {
  const t = await c.tree();
  const names = [...new Set(t.nodes.map((n) => n.name))];
  return names
    .map((n) => [n, editDistance(n.toLowerCase(), name.toLowerCase(), 3)] as const)
    .filter(([, d]) => d <= 2)
    .sort((a, b) => a[1] - b[1])
    .slice(0, 3)
    .map(([n]) => n);
}

export async function resolveVersions(c: Ctx, raw: string): Promise<{ name: string; keys: { key: string; version: string }[]; asked?: string }> {
  const { name, version } = splitName(raw);
  const rows = (await read(c.org, Q("version_resolve"), { scanId: c.project.scanId, name })) as { key: string; version: string }[];
  const keys = version ? rows.filter((r) => r.version === version) : rows;
  return { name, keys: keys.length ? keys : version ? [] : rows, asked: version };
}

// ───────────── tools ─────────────
const overview: Tool = {
  label: "Read the project's findings",
  spec: { name: "project_overview", description: "The project's verdict, size, and every open finding (malware, suspicious releases, vulnerabilities) with its route from the project.", parameters: { type: "object", properties: {} } },
  async run(c) {
    const findings = (await loadFindings(c.org, c.project)).filter((f) => f.status !== "skipped");
    const verdict = verdictOf(findings);
    const open = findings.filter((f) => f.status === "open" || f.status === "confirmed");
    const lines = open.slice(0, 8).map((f) => `${f.severity} ${f.signal.replace(/_/g, " ")}: ${f.name}@${f.version}`);
    return {
      outcome: "answered",
      summary: open.length
        ? `${c.project.name} is ${verdict}: ${open.length} open finding${open.length === 1 ? "" : "s"}${lines.length ? ` (${lines.join("; ")}${open.length > lines.length ? "; …" : ""})` : ""}.`
        : `${c.project.name} has no open findings${findings.length ? ` (${findings.length} reviewed)` : ""}.`,
      data: { verdict, findings: open.slice(0, 20).map((f) => ({ id: f.id, package: `${f.name}@${f.version}`, signal: f.signal, severity: f.severity, title: untrusted(f.title), route: route(f.path), fix: f.fix ?? null, advisories: f.advisories.map((a) => a.id) })) },
      query: "findings_list",
      evidence: merge(...open.slice(0, 8).map((f) => ev(f.path, pathEdges(f.path)))),
    };
  },
};

const exposures: Tool = {
  label: "Traced exposures",
  spec: { name: "trace_exposures", description: "Every advisory (malware first) that hits a version this project installs, with the shortest route from the project to it and the fixed version.", parameters: { type: "object", properties: {} } },
  async run(c) {
    const rows = await read(c.org, Q("exposure_paths"), { projectId: c.project.id, scanId: c.project.scanId });
    if (!rows.length) return { outcome: "not_in_graph", summary: `No advisory in OSV.dev affects anything ${c.project.name} installs.`, data: [], query: "exposure_paths", evidence: ev([root(c)]) };
    const t = await c.tree();
    const seen = new Map<string, any>();
    for (const r of rows) {
      const path = r.ownRoute && r.path.length ? r.path : pathTo(t, r.version);
      const cur = seen.get(r.version) ?? { version: r.version, path, malware: false, advisories: [] as string[], fixed: null as string | null, severity: "low" };
      cur.malware ||= r.kind === "malware";
      cur.advisories.push(r.advisory);
      // The version that clears every advisory on it, not just the first one listed.
      if (r.fixed && (!cur.fixed || compareVersions(r.fixed, cur.fixed) > 0)) cur.fixed = r.fixed;
      seen.set(r.version, cur);
    }
    const list = [...seen.values()].sort((a, b) => Number(b.malware) - Number(a.malware) || a.path.length - b.path.length);
    const bad = list.filter((x) => x.malware);
    const top = (bad.length ? bad : list).slice(0, 6);
    const name = (k: string) => short(k);
    return {
      outcome: "answered",
      summary:
        (bad.length
          ? `${bad.length} installed version${bad.length === 1 ? " is" : "s are"} named in malware advisories: ${bad.slice(0, 6).map((x) => `${name(x.version)} (via ${route(x.path)})`).join("; ")}.`
          : `No malware advisory matches, but ${list.length} version${list.length === 1 ? " has" : "s have"} known vulnerabilities: ${top.map((x) => `${name(x.version)} (${x.advisories[0]})`).join(", ")}.`) +
        (bad.length && list.length > bad.length ? ` ${list.length - bad.length} more have ordinary vulnerabilities.` : ""),
      data: list.slice(0, 25).map((x) => ({ package: name(x.version), malware: x.malware, advisories: x.advisories.slice(0, 4), route: route(x.path), fixedIn: x.fixed })),
      query: "exposure_paths",
      evidence: merge(...top.map((x) => ev([...x.path, ...x.advisories.slice(0, 2).map((a: string) => `advisory/${a}`)], [...pathEdges(x.path), ...x.advisories.slice(0, 2).map((a: string) => [`advisory/${a}`, x.version, "AFFECTS"] as [string, string, string])]))),
    };
  },
};

const explain: Tool = {
  label: "Looked up a package",
  spec: {
    name: "explain_package",
    description: "Everything about one package the project installs: its versions, advisories, who published and maintains it, the previous release, install scripts, and every route from the project to it. Pass the package name, optionally with @version.",
    parameters: { type: "object", properties: { name: { type: "string", description: "Package name, e.g. chalk or @tanstack/react-router or litellm@1.82.8" } }, required: ["name"] },
  },
  async run(c, args) {
    const raw = str(args.name);
    if (!raw) return { outcome: "unknown_name", summary: "No package name was given.", data: null, query: "version_resolve", evidence: ev() };
    const { name, keys, asked } = await resolveVersions(c, raw);
    if (!keys.length) {
      const near = await suggest(c, name);
      return {
        outcome: "unknown_name",
        summary: `${c.project.name} doesn't install ${asked ? `${name}@${asked}` : name}.${near.length ? ` Closest names in the project: ${near.join(", ")}.` : ""}`,
        data: { found: false, didYouMean: near },
        query: "version_resolve",
        evidence: ev(),
      };
    }
    const out: any[] = [];
    let evidence = ev();
    for (const { key } of keys.slice(0, 3)) {
      const [[x], routes, prior] = await Promise.all([
        read(c.org, Q("version_explain"), { key, scanId: c.project.scanId }),
        read(c.org, Q("version_routes"), { projectId: c.project.id, key }),
        read(c.org, Q("verdicts_prior"), { keys: [key] }),
      ]);
      const paths: string[][] = routes.length ? routes.map((r) => r.path) : [pathTo(await c.tree(), key)];
      const v = x?.version ?? {};
      out.push({
        package: short(key),
        published: v.published_at ? new Date(v.published_at).toISOString().slice(0, 10) : null,
        removedFromRegistry: !!v.removed,
        installScripts: v.has_install_script ? untrusted(v.install_scripts ?? "yes") : null,
        provenance: v.has_provenance ?? null,
        devOnly: x?.dev ?? null,
        previous: x?.previous ? short(x.previous) : null,
        publishers: x?.publishers ?? [],
        maintainers: (x?.maintainers ?? []).slice(0, 10),
        dependents: x?.dependents ?? null,
        advisories: (x?.advisories ?? []).filter((a: any) => a?.id).map((a: any) => ({ id: a.id, kind: a.kind, summary: untrusted(a.summary) })),
        routes: paths.slice(0, 3).map(route),
        humanVerdicts: prior.map((p) => ({ verdict: p.verdict, signal: p.signal, note: untrusted(p.note ?? "") })),
      });
      evidence = merge(
        evidence,
        ...paths.slice(0, 3).map((p) => ev(p, pathEdges(p))),
        ev(
          x?.publisherKeys ?? [],
          (x?.publisherKeys ?? []).map((a: string) => [a, key, "PUBLISHED"] as [string, string, string]),
        ),
        ev(
          (x?.advisories ?? []).filter((a: any) => a?.id).map((a: any) => `advisory/${a.id}`),
          (x?.advisories ?? []).filter((a: any) => a?.id).map((a: any) => [`advisory/${a.id}`, key, "AFFECTS"] as [string, string, string]),
        ),
      );
    }
    // Flagged versions first, each described on its own so facts never cross versions.
    const risk = (o: any) => (o.advisories.some((a: any) => a.kind === "malware") || o.removedFromRegistry ? 2 : o.advisories.length ? 1 : 0);
    out.sort((a, b) => risk(b) - risk(a));
    const line = (o: any) =>
      `${o.package}${o.routes[0] ? ` reaches you via ${o.routes[0]}` : ""}${o.devOnly ? " (dev only)" : ""}. ` +
      (o.advisories.length ? `Advisories: ${o.advisories.slice(0, 4).map((a: any) => `${a.id}${a.kind === "malware" ? " (malware)" : ""}`).join(", ")}. ` : "No advisories. ") +
      (o.publishers.length ? `Published by ${o.publishers.join(", ")}. ` : "") +
      (o.removedFromRegistry ? "The registry no longer serves this version. " : "") +
      (o.installScripts ? "It runs an install script. " : "") +
      (o.humanVerdicts.length ? `Earlier human verdict: ${o.humanVerdicts[0].verdict}.` : "");
    return {
      outcome: "answered",
      summary: (out.length > 1 ? `${c.project.name} installs ${out.length} versions of ${name}. ` : "") + out.map((o) => line(o).trim()).join(" "),
      data: out,
      query: "version_explain",
      evidence,
    };
  },
};

const topAccounts: Tool = {
  label: "Ranked maintainer accounts",
  spec: { name: "top_accounts", description: "The accounts that can publish the largest share of this project's dependency tree, weighted by PageRank. One hijacked login reaches all of those versions.", parameters: { type: "object", properties: {} } },
  async run(c) {
    const list = await accounts(c.org, c.project, 10);
    if (!list.length) return { outcome: "not_in_graph", summary: "No maintainer data for this project's packages.", data: [], query: "accounts_reach", evidence: ev([root(c)]) };
    return {
      outcome: "answered",
      summary: `The accounts with the most reach: ${list.slice(0, 5).map((a) => `${a.login} (${a.versions} versions, ${(a.share * 100).toFixed(0)}%${a.flagged ? ", touches a flagged version" : ""})`).join(", ")}.`,
      data: list.map((a) => ({ login: a.login, kind: a.kind, versions: a.versions, share: Number(a.share.toFixed(3)), pagerankWeight: Number(a.weight.toFixed(4)), flagged: a.flagged })),
      query: "accounts_reach",
      evidence: ev(list.slice(0, 5).map((a) => a.key)),
    };
  },
};

const worm: Tool = {
  label: "Simulated a worm",
  spec: {
    name: "simulate_worm",
    description: "Simulate a Shai-Hulud style worm starting from one maintainer account: wave by wave, which accounts and versions in this project it would poison.",
    parameters: { type: "object", properties: { login: { type: "string", description: "Maintainer login, e.g. qix" }, waves: { type: "integer", minimum: 1, maximum: 6 } }, required: ["login"] },
  },
  async run(c, args) {
    const login = str(args.login, 100).replace(/^@/, "");
    try {
      const r = await simulateWorm(c.org, c.project, login, Math.min(6, Math.max(1, Number(args.waves) || 4)));
      const [start] = await read(c.org, Q("account_resolve"), { scanId: c.project.scanId, login });
      const poisoned = r.waves.flatMap((w) => w.poisoned);
      return {
        outcome: "answered",
        summary: `Starting from ${r.start}, the worm poisons ${poisoned.length} of ${r.totalVersions} versions (${(r.poisonedShare * 100).toFixed(1)}%) and takes over ${r.compromisedAccounts} account${r.compromisedAccounts === 1 ? "" : "s"} in ${r.waves.length} wave${r.waves.length === 1 ? "" : "s"}${r.waves[0]?.poisoned.length ? `; wave 1 hits ${r.waves[0].poisoned.slice(0, 4).map(short).join(", ")}` : ""}.`,
        data: { ...r, waves: r.waves.map((w) => ({ wave: w.wave, accounts: w.accounts.slice(0, 15), poisoned: w.poisoned.slice(0, 15).map(short), poisonedCount: w.poisoned.length })) },
        query: "worm_wave",
        evidence: ev([start.key, ...r.waves[0].poisoned.slice(0, 12)], r.waves[0].poisoned.slice(0, 12).map((k) => [start.key, k, "MAINTAINS"] as [string, string, string])),
      };
    } catch (e: any) {
      if (e.statusCode !== 404) throw e;
      const near = (await accounts(c.org, c.project, 50)).map((a) => a.login).filter((l) => editDistance(l.toLowerCase(), login.toLowerCase(), 3) <= 2);
      return { outcome: "unknown_name", summary: `${login || "That account"} doesn't maintain anything in ${c.project.name}.${near.length ? ` Did you mean ${near.slice(0, 3).join(", ")}?` : ""}`, data: { found: false, didYouMean: near.slice(0, 3) }, query: "account_resolve", evidence: ev() };
    }
  },
};

const mcp: Tool = {
  label: "Checked MCP servers",
  spec: { name: "mcp_servers", description: "The MCP servers this config launches, whether each is pinned to a version, the package it runs, and any advisory anywhere under it.", parameters: { type: "object", properties: {} } },
  async run(c) {
    const rows = await read(c.org, Q("mcp_exposure"), { projectId: c.project.id });
    if (!rows.length) return { outcome: "not_in_graph", summary: `${c.project.name} declares no MCP servers.`, data: [], query: "mcp_exposure", evidence: ev([root(c)]) };
    const risky = rows.filter((r) => !r.pinned || (r.advisories ?? []).filter(Boolean).length);
    return {
      outcome: "answered",
      summary: `${rows.length} MCP server${rows.length === 1 ? "" : "s"}; ${risky.length ? risky.map((r) => `${r.name}${r.pinned ? "" : " is unpinned"}${(r.advisories ?? []).filter(Boolean).length ? ` (advisories: ${r.advisories.filter(Boolean).slice(0, 3).join(", ")})` : ""}`).join("; ") : "all pinned with no advisories"}.`,
      data: rows.map((r) => ({ name: r.name, client: r.client, command: untrusted(r.command), pinned: !!r.pinned, runs: r.packageKey ? short(r.packageKey) : null, advisories: (r.advisories ?? []).filter(Boolean) })),
      query: "mcp_exposure",
      evidence: ev([root(c), ...rows.filter((r) => r.packageKey).map((r) => r.packageKey)], rows.filter((r) => r.packageKey).map((r) => [root(c), r.packageKey, "RUNS"] as [string, string, string])),
    };
  },
};

const pointInTime: Tool = {
  label: "Checked a past date",
  spec: {
    name: "exposed_on",
    description: "Were we exposed on a given date? Uses the latest scan taken on or before that date and says whether each advisory was already public then.",
    parameters: { type: "object", properties: { date: { type: "string", description: "ISO date, e.g. 2025-09-08" } }, required: ["date"] },
  },
  async run(c, args) {
    const d = new Date(str(args.date, 40));
    if (Number.isNaN(d.getTime())) return { outcome: "unknown_name", summary: `"${str(args.date, 40)}" isn't a date I can read. Use YYYY-MM-DD.`, data: null, query: "point_in_time", evidence: ev() };
    const end = new Date(d.getTime() + 86_400_000 - 1);
    const rows = await read(c.org, Q("point_in_time"), { projectId: c.project.id, t: end.getTime(), iso: end.toISOString() });
    const day = d.toISOString().slice(0, 10);
    if (!rows.length) return { outcome: "not_in_graph", summary: `Unknown: no scan of ${c.project.name} on or before ${day} shows an affected version, and the earliest scan may be later than that date. This is not evidence that the project was safe then.`, data: [], query: "point_in_time", evidence: ev() };
    return {
      outcome: "answered",
      summary: `On ${day} (scan ${rows[0].scan}) ${c.project.name} had ${new Set(rows.map((r) => r.version)).size} affected versions: ${rows.slice(0, 5).map((r) => `${short(r.version)} (${r.advisory}${r.knownAtTheTime === false ? ", not public yet" : r.knownAtTheTime ? ", already public" : ""})`).join("; ")}.`,
      data: rows.slice(0, 25).map((r) => ({ ...r, version: short(r.version) })),
      query: "point_in_time",
      evidence: ev(rows.slice(0, 8).map((r) => r.version)),
    };
  },
};

const searchAdvisories: Tool = {
  label: "Searched advisories",
  spec: {
    name: "search_advisories",
    description: "Full-text search over the summaries of advisories stored in the graph (e.g. 'credential stealer', 'phishing').",
    parameters: { type: "object", properties: { text: { type: "string" } }, required: ["text"] },
  },
  async run(c, args) {
    // RediSearch query syntax: keep words only so user text can't change the query.
    const words = str(args.text, 120).toLowerCase().match(/[a-z0-9]{3,}/g) ?? [];
    if (!words.length) return { outcome: "unknown_name", summary: "Give me a few words to search for.", data: [], query: "advisories_search", evidence: ev() };
    const rows = await read(c.org, Q("advisories_search"), { text: words.slice(0, 6).join("|") });
    if (!rows.length) return { outcome: "not_in_graph", summary: `No stored advisory mentions ${words.join(" ")}.`, data: [], query: "advisories_search", evidence: ev() };
    return {
      outcome: "answered",
      summary: `Matching advisories: ${rows.map((r) => `${r.id} (${untrusted(r.summary).slice(0, 80)})`).join("; ")}.`,
      data: rows.map((r) => ({ id: r.id, kind: r.kind, summary: untrusted(r.summary), url: r.url })),
      query: "advisories_search",
      evidence: ev(rows.map((r) => `advisory/${r.id}`)),
    };
  },
};

const chokepoints: Tool = {
  label: "Found chokepoints",
  spec: { name: "chokepoints", description: "The versions the most dependency paths run through (betweenness centrality): patching or pinning these protects the most.", parameters: { type: "object", properties: {} } },
  async run(c) {
    const rows = await read(c.org, Q("algo_chokepoints"), { scanId: c.project.scanId });
    if (!rows.length) return { outcome: "not_in_graph", summary: "The tree is too flat to have chokepoints.", data: [], query: "algo_chokepoints", evidence: ev() };
    return {
      outcome: "answered",
      summary: `The busiest chokepoints: ${rows.slice(0, 5).map((r) => short(r.key)).join(", ")}.`,
      data: rows.map((r) => ({ package: short(r.key), betweenness: Number(Number(r.score).toFixed(1)) })),
      query: "algo_chokepoints",
      evidence: ev(rows.slice(0, 5).map((r) => r.key)),
    };
  },
};

/** Memory, read before anything else: human verdicts on this project's flagged versions and earlier investigations. */
export const recall: Tool = {
  label: "Recalled memory",
  spec: { name: "recall_memory", description: "Earlier human verdicts on this project's flagged versions and earlier investigations of this project.", parameters: { type: "object", properties: {} } },
  async run(c) {
    const findings = await loadFindings(c.org, c.project);
    const [prior, recent] = await Promise.all([
      read(c.org, Q("verdicts_prior"), { keys: [...new Set(findings.map((f) => f.versionKey))] }),
      read(c.org, Q("investigation_recent"), { projectId: c.project.id }),
    ]);
    const human = prior.map((p) => ({ package: short(p.version), signal: p.signal, verdict: p.verdict, note: untrusted(p.note ?? ""), sameProject: p.projectId === c.project.id }));
    const skipped = findings.filter((f) => f.status === "skipped");
    const parts = [
      human.length ? `${human.length} human verdict${human.length === 1 ? "" : "s"} on these versions (${human.slice(0, 4).map((h) => `${h.package} ${h.signal.replace(/_/g, " ")}: ${h.verdict}`).join("; ")})` : "",
      skipped.length ? `${skipped.length} finding${skipped.length === 1 ? " was" : "s were"} skipped by memory or a learned rule` : "",
      recent.length ? `${recent.length} earlier investigation${recent.length === 1 ? "" : "s"} of this project` : "",
    ].filter(Boolean);
    return {
      outcome: parts.length ? "from_memory" : "not_in_graph",
      summary: parts.length ? `Memory: ${parts.join("; ")}.` : "Nothing in memory about this project yet.",
      data: { humanVerdicts: human, skipped: skipped.map((f) => ({ package: `${f.name}@${f.version}`, signal: f.signal, note: untrusted(f.statusNote ?? "") })), earlier: recent.map((r) => ({ question: untrusted(r.question), answer: untrusted(r.answer ?? "").slice(0, 300), at: r.at })) },
      query: "verdicts_prior",
      evidence: ev(prior.map((p) => p.version)),
    };
  },
};

export const TOOLS: Tool[] = [overview, exposures, explain, topAccounts, worm, mcp, pointInTime, searchAdvisories, chokepoints];
export const toolByName = new Map([...TOOLS, recall].map((t) => [t.spec.name, t]));
export const queryText = (r: ToolResult) => shown(r.query);
export { COMPROMISE };
