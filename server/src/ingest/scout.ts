import { createHash, randomUUID } from "node:crypto";
import pLimit from "p-limit";
import { config } from "../config.ts";
import { batched, run } from "../db.ts";
import { Q } from "../queries.ts";
import { ensureSchema } from "../schema.ts";
import { getProject, projectTree, triage } from "../analysis.ts";
import { createTask } from "../agents/tasks.ts";
import type { Ecosystem, ScanEvent } from "../types.ts";
import { npmKey, npmPackageKey, parseInput, pypiKey, pypiPackageKey, type Parsed, type Pkg } from "./parsers.ts";
import { scriptFlags, scriptText, typosquatOf } from "./heuristics.ts";
import {
  classifyAdvisory,
  depsDevBatch,
  depsDevDependencies,
  depsDevKey,
  installHooks,
  npmHistory,
  npmLatest,
  npmVersion,
  osvBatch,
  osvVuln,
  pypiProject,
  reach,
  topPackages,
  type NpmHistory,
  type NpmVersionDoc,
  type PypiProject,
} from "./feeds.ts";

type Emit = (e: ScanEvent) => void;
const pkgKey = (eco: Ecosystem, name: string) => (eco === "PyPI" ? pypiPackageKey(name) : npmPackageKey(name));
const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || "project";
const clean = <T extends Record<string, unknown>>(o: T) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined && v !== null)) as T;

/** Lockfiles without a real project name ("pnpm-lock", "Claude Code MCP setup") get a fingerprint of their direct deps. */
const GENERIC = /^(package-lock|pnpm-lock|yarn|bun|uv|poetry|requirements.*|.* MCP setup)$/i;
function identify(p: Parsed, explicit: boolean): string {
  let fp = "";
  if (!explicit && GENERIC.test(p.name)) {
    const names = p.mcp.length ? p.mcp.map((m) => m.name) : p.direct.map((d) => d.key.replace(/@[^@]*$/, ""));
    fp = createHash("sha1").update([...new Set(names)].sort().join(",")).digest("hex").slice(0, 4);
    p.name = `${p.name} (${fp})`;
  }
  return `${slug(p.name)}-${createHash("sha1").update(`${p.name}|${p.source}|${fp}`).digest("hex").slice(0, 6)}`;
}

// Two scans of one project must not interleave (the second would switch latest_scan under the first).
const locks = new Map<string, Promise<unknown>>();
function serialized<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const next = (locks.get(key) ?? Promise.resolve()).catch(() => {}).then(fn);
  locks.set(key, next);
  return next.finally(() => locks.get(key) === next && locks.delete(key));
}

/** Scout agent: parse -> enrich from public feeds -> write the workspace graph -> triage -> hand off to the Analyst. */
export async function scan(org: string, input: { filename: string; content: string; name?: string }, emit: Emit = () => {}): Promise<string> {
  emit({ type: "progress", stage: "Reading", message: `Reading ${input.filename}`, pct: 2 });
  const parsed = parseInput(input.filename, input.content);
  if (input.name) parsed.name = input.name;
  const projectId = identify(parsed, !!input.name);
  return serialized(`${org}|${projectId}`, () => scanProject(org, projectId, parsed, emit));
}

async function scanProject(org: string, projectId: string, parsed: Parsed, emit: Emit): Promise<string> {
  await ensureSchema(org);
  for (const m of parsed.mcp) m.key = `mcp/${projectId}/${m.name}`;
  if (parsed.mcp.length) await expandMcp(parsed, emit);
  const pkgs = [...parsed.packages.values()];
  if (!pkgs.length && !parsed.mcp.length) throw new Error("No registry packages found in this file.");
  const npm = pkgs.filter((p) => p.ecosystem === "npm");
  const py = pkgs.filter((p) => p.ecosystem === "PyPI");
  emit({ type: "progress", stage: "Reading", message: `${pkgs.length} package versions${npm.length && py.length ? ` (${npm.length} npm, ${py.length} PyPI)` : ""}, ${parsed.edges.length} dependency edges, ${parsed.direct.length} direct`, pct: 8 });
  const limit = pLimit(config.concurrency);

  // ── Advisories ──
  emit({ type: "progress", stage: "Advisories", message: "Checking OSV.dev for malware and vulnerability advisories", pct: 12 });
  const ids = await osvBatch(pkgs.map((p) => ({ name: p.name, version: p.version, ecosystem: p.ecosystem })));
  let missing = 0;
  const vulns = new Map((await Promise.all([...new Set(ids.flat())].map((id) => limit(async () => [id, await osvVuln(id).catch(() => (missing++, null))] as const)))).filter(([, v]) => v));
  const advisories: any[] = [];
  pkgs.forEach((p, i) => {
    for (const id of ids[i] ?? []) {
      const v = vulns.get(id);
      const c = v && classifyAdvisory(v, p.name, p.version);
      if (c) advisories.push({ ...c, version: p.key });
    }
  });
  const malwareVersions = new Set(advisories.filter((a) => a.kind === "malware").map((a) => a.version)).size;
  emit({ type: "progress", stage: "Advisories", message: `${vulns.size} advisories match; ${malwareVersions} versions hit by malware advisories${missing ? `; ${missing} advisories couldn't be loaded` : ""}`, pct: 22 });

  emit({ type: "progress", stage: "Provenance", message: "Fetching publish dates and build provenance from deps.dev", pct: 25 });
  const dd = await depsDevBatch(pkgs).catch((e) => (console.warn("[deps.dev]", e.message), new Map()));

  const rows: Rows = { versions: [], maintainers: [], publishers: [], precedes: [] };
  if (npm.length) await enrichNpm(parsed, npm, dd, new Set(advisories.map((a) => a.version)), rows, limit, emit);
  if (py.length) await enrichPypi(parsed, py, dd, rows, limit, emit);

  emit({ type: "progress", stage: "Reach", message: "Looking up how widely each package is used (ecosyste.ms)", pct: 70 });
  const packageRows: any[] = [];
  for (const [eco, list] of [["npm", npm], ["PyPI", py]] as const) {
    if (!list.length) continue;
    const names = [...new Set(list.map((p) => p.name))];
    const r = await reach(eco, names);
    const top = r.size ? await topPackages(eco) : new Map<string, number>();
    for (const name of names) {
      const x = r.get(name);
      packageRows.push({ key: pkgKey(eco, name), typosquatOf: top.size ? typosquatOf(name, x?.downloads, top) : null, props: clean({ name, ecosystem: eco, dependents: x?.dependents, downloads: x?.downloads }) });
    }
  }

  // ── Write the graph ──
  emit({ type: "progress", stage: "Graph", message: "Writing the dependency graph to FalkorDB", pct: 78 });
  const scanId = `scan-${randomUUID().slice(0, 8)}`;
  await run(org, Q("project_upsert"), { id: projectId, key: `project/${projectId}`, name: parsed.name, kind: parsed.kind, source: parsed.source, scanId, at: Date.now() });
  await batched(org, Q("packages_upsert"), packageRows);
  await batched(org, Q("versions_upsert"), rows.versions);
  await run(org, Q("edges_release"), { projectId });
  await batched(org, Q("edges_claim"), parsed.edges, { projectId });
  await run(org, Q("direct_upsert"), { projectId, rows: parsed.direct });
  await batched(org, Q("scan_saw"), pkgs.map((p) => ({ key: p.key, dev: p.dev })), { scanId });
  await batched(org, Q("maintainers_upsert"), rows.maintainers);
  await batched(org, Q("publishers_upsert"), rows.publishers);
  await batched(org, Q("precedes_upsert"), rows.precedes);
  await batched(org, Q("advisories_upsert"), advisories);
  await run(org, Q("mcp_reset"), { projectId });
  const mcpRow = (m: Parsed["mcp"][number]) => ({ key: m.key, name: m.name, client: m.client, command: m.command, pinned: m.pinned, version: m.resolvedKey ?? null });
  const withPkg = parsed.mcp.filter((m) => m.resolvedKey).map(mcpRow);
  const noPkg = parsed.mcp.filter((m) => !m.resolvedKey).map(mcpRow);
  if (withPkg.length) await run(org, Q("mcp_upsert"), { projectId, rows: withPkg });
  if (noPkg.length) await run(org, Q("mcp_upsert_nopkg"), { projectId, rows: noPkg });

  emit({ type: "progress", stage: "Algorithms", message: "Running PageRank over the dependency graph", pct: 86 });
  const [edges] = await run(org, Q("version_edges_exist"));
  if (edges?.any) await run(org, Q("algo_pagerank"));
  else await run(org, Q("rank_default"));

  emit({ type: "progress", stage: "Triage", message: "Tracing routes to every flagged version and checking memory", pct: 90 });
  const project = await getProject(org, projectId);
  const { findings, verdict } = await triage(org, project, await projectTree(org, project));
  await createTask(org, projectId, "analyze", "analyst", { scanId });
  const open = findings.filter((f) => f.status !== "skipped").length;
  const skipped = findings.length - open;
  emit({ type: "progress", stage: "Done", message: `Verdict: ${verdict}. ${open} finding${open === 1 ? "" : "s"}${skipped ? `, ${skipped} skipped by memory` : ""}. The Analyst has been asked to review it.`, pct: 100 });
  emit({ type: "done", projectId });
  return projectId;
}

interface Rows {
  versions: any[];
  maintainers: any[];
  publishers: any[];
  precedes: any[];
}

// ───────────── npm: who published each release, maintainers, install scripts, provenance, history ─────────────
async function enrichNpm(parsed: Parsed, pkgs: Pkg[], dd: Map<string, any>, flagged: Set<string>, rows: Rows, limit: ReturnType<typeof pLimit>, emit: Emit) {
  let n = 0;
  const docs = new Map<string, NpmVersionDoc | null | undefined>();
  await Promise.all(
    pkgs.map((p) =>
      limit(async () => {
        docs.set(p.key, await npmVersion(p.name, p.version).catch(() => undefined));
        if (++n % 50 === 0) emit({ type: "progress", stage: "Registry", message: `npm: ${n} of ${pkgs.length} versions`, pct: 28 + Math.round((n / pkgs.length) * 30) });
      }),
    ),
  );
  // Release history only where it matters: direct deps, removed versions, advisory hits, install scripts, fresh releases.
  const direct = new Set(parsed.direct.map((d) => d.key));
  const now = Date.now();
  const wanted = pkgs
    .filter((p) => {
      const doc = docs.get(p.key);
      const at = Date.parse(dd.get(depsDevKey("npm", p.name, p.version))?.publishedAt ?? "");
      return direct.has(p.key) || doc === null || flagged.has(p.key) || p.lockInstallScript || Object.keys(installHooks(doc?.scripts)).length > 0 || now - at < 30 * 86400_000;
    })
    .slice(0, 250);
  emit({ type: "progress", stage: "History", message: `Reading release history for ${wanted.length} npm packages`, pct: 60 });
  const hist = new Map<string, NpmHistory | null>();
  await Promise.all(wanted.map((p) => limit(async () => hist.set(p.name, await npmHistory(p.name).catch(() => null)))));

  // One identity per account, and one per trusted-publishing pipeline (the same CI is never a "new publisher").
  const who = (user: string | undefined, trusted: boolean | undefined, name: string) =>
    !user ? null : trusted ? { key: `workflow/npm:${name}`, login: `CI for ${name}`, kind: "workflow" } : { key: `npm-user/${user}`, login: user, kind: "user" };
  const seen = new Set<string>();
  for (const p of pkgs) {
    const doc = docs.get(p.key);
    const h = hist.get(p.name);
    const ddv = dd.get(depsDevKey("npm", p.name, p.version));
    const hooks = installHooks(doc?.scripts);
    const flags = scriptFlags(hooks);
    const removed = (doc === null && !!h?.time?.[p.version] && !h.versions[p.version]) || doc?.description === "security holding package" || /-security$/.test(p.version);
    rows.versions.push({
      key: p.key,
      pkg: npmPackageKey(p.name),
      observed: true,
      flags: flags.length ? flags : null,
      removed: removed || null,
      props: clean({
        name: p.name,
        version: p.version,
        ecosystem: "npm",
        has_install_script: Object.keys(hooks).length > 0 || !!p.lockInstallScript || undefined,
        install_scripts: Object.keys(hooks).length ? Object.keys(hooks) : undefined,
        script_text: scriptText(hooks),
        has_provenance: doc === null && !ddv ? undefined : !!doc?.dist?.attestations || !!ddv?.slsaProvenances?.length,
        published_at: ddv?.publishedAt ?? h?.time?.[p.version],
      }),
    });
    for (const login of (doc?.maintainers ?? []).map((m) => m.name).concat(doc ? [] : h?.maintainers ?? [])) {
      if (!login || seen.has(`${login}|${p.name}`)) continue;
      seen.add(`${login}|${p.name}`);
      rows.maintainers.push({ key: `npm-user/${login}`, login, kind: "user", pkg: npmPackageKey(p.name) });
    }
    const pub = who(doc?._npmUser?.name ?? h?.versions[p.version]?.user, doc ? !!doc._npmUser?.trustedPublisher : h?.versions[p.version]?.trusted, p.name);
    if (pub) rows.publishers.push({ ...pub, version: p.key });

    // The release before this one (by publish time, skipping prereleases).
    const mine = Date.parse(h?.time?.[p.version] ?? "");
    if (h && !Number.isNaN(mine)) {
      const prev = Object.entries(h.time)
        .filter(([v, t]) => h.versions[v] && v !== p.version && !v.includes("-") && Date.parse(t) < mine)
        .sort((a, b) => Date.parse(a[1]) - Date.parse(b[1]))
        .pop()?.[0];
      if (prev) {
        const pv = h.versions[prev];
        const prevKey = npmKey(p.name, prev);
        if (!parsed.packages.has(prevKey))
          rows.versions.push({ key: prevKey, pkg: npmPackageKey(p.name), props: clean({ name: p.name, version: prev, ecosystem: "npm", has_install_script: Object.keys(pv.hooks).length > 0, has_provenance: pv.attested, published_at: h.time[prev] }) });
        const prevPub = who(pv.user, pv.trusted, p.name);
        if (prevPub) rows.publishers.push({ ...prevPub, version: prevKey });
        rows.precedes.push({ prev: prevKey, key: p.key });
      }
    }
  }
}

// ───────────── PyPI: owners and organizations, release dates, removed releases, history ─────────────
async function enrichPypi(parsed: Parsed, pkgs: Pkg[], dd: Map<string, any>, rows: Rows, limit: ReturnType<typeof pLimit>, emit: Emit) {
  const names = [...new Set(pkgs.map((p) => p.name))];
  emit({ type: "progress", stage: "Registry", message: `Fetching owners and release history for ${names.length} PyPI projects`, pct: 62 });
  const projects = new Map<string, PypiProject | null>();
  await Promise.all(names.map((n) => limit(async () => projects.set(n, await pypiProject(n).catch(() => null)))));
  const seen = new Set<string>();
  for (const p of pkgs) {
    const proj = projects.get(p.name);
    const rel = proj?.releases ?? {};
    // PEP 440: "1.1" and "1.1.0" are the same release (deps.dev pads versions, PyPI lists them as published).
    const pep = (v: string) => v.toLowerCase().replace(/(\.0+)+$/, "");
    const mine = rel[p.version] ?? Object.entries(rel).find(([v]) => pep(v) === pep(p.version))?.[1];
    rows.versions.push({
      key: p.key,
      pkg: pypiPackageKey(p.name),
      observed: true,
      flags: null,
      removed: (!!proj && !mine) || null, // PyPI deletes malware releases; a pinned version it no longer lists was removed
      props: clean({ name: p.name, version: p.version, ecosystem: "PyPI", published_at: dd.get(depsDevKey("PyPI", p.name, p.version))?.publishedAt ?? mine?.time ?? undefined, yanked: mine?.yanked || undefined }),
    });
    const owners = (proj?.owners ?? []).map((u) => ({ key: `pypi-user/${u}`, login: u, kind: "user" }));
    if (proj?.organization) owners.push({ key: `pypi-org/${proj.organization}`, login: `${proj.organization} (PyPI organization)`, kind: "org" });
    for (const o of owners) {
      if (seen.has(`${o.key}|${p.name}`)) continue;
      seen.add(`${o.key}|${p.name}`);
      rows.maintainers.push({ ...o, pkg: pypiPackageKey(p.name) });
    }
    if (mine?.time) {
      const prev = Object.entries(rel)
        .filter(([v, r]) => r.time && r.time < mine.time! && /^[\d.]+$/.test(v))
        .sort((a, b) => (a[1].time! < b[1].time! ? -1 : 1))
        .pop()?.[0];
      if (prev) {
        const prevKey = pypiKey(p.name, prev);
        if (!parsed.packages.has(prevKey)) rows.versions.push({ key: prevKey, pkg: pypiPackageKey(p.name), props: clean({ name: p.name, version: prev, ecosystem: "PyPI", published_at: rel[prev].time ?? undefined }) });
        rows.precedes.push({ prev: prevKey, key: p.key });
      }
    }
  }
}

/** MCP servers become direct dependencies of an "agent-config" project; their dependency trees come from deps.dev. */
async function expandMcp(parsed: Parsed, emit: Emit) {
  for (const m of parsed.mcp) {
    if (!m.packageName || !m.ecosystem) continue;
    const eco = m.ecosystem;
    const version = m.version ?? (eco === "PyPI" ? (await pypiProject(m.packageName).catch(() => null))?.latest || null : await npmLatest(m.packageName).catch(() => null));
    if (!version) continue;
    emit({ type: "progress", stage: "Reading", message: `MCP server "${m.name}" runs ${m.packageName}@${version} from ${eco}${m.pinned ? "" : " (not pinned: resolved to today's latest)"}`, pct: 5 });
    const key = (n: string, v: string) => (eco === "PyPI" ? pypiKey(n, v) : npmKey(n, v));
    const add = (n: string, v: string): Pkg => {
      const k = key(n, v);
      if (!parsed.packages.has(k)) parsed.packages.set(k, { key: k, name: eco === "PyPI" ? n.toLowerCase().replace(/[-_.]+/g, "-") : n, version: v, ecosystem: eco, dev: false });
      return parsed.packages.get(k)!;
    };
    m.resolvedKey = add(m.packageName, version).key;
    if (!parsed.direct.some((d) => d.key === m.resolvedKey)) parsed.direct.push({ key: m.resolvedKey, dev: false });
    const graph = await depsDevDependencies(eco, m.packageName, version).catch(() => null);
    if (!graph) continue;
    const keys = graph.nodes.map((n) => add(n.versionKey.name, n.versionKey.version).key);
    for (const e of graph.edges) if (keys[e.fromNode] !== keys[e.toNode]) parsed.edges.push({ from: keys[e.fromNode], to: keys[e.toNode] });
  }
}
