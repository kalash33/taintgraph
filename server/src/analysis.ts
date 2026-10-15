import { createHash } from "node:crypto";
import { read, run } from "./db.ts";
import { Q } from "./queries.ts";
import {
  COMPROMISE,
  type AccountView,
  type AdvisoryRef,
  type DependencyGraph,
  type Ecosystem,
  type FindingStatus,
  type FindingView,
  type GraphNode,
  type McpServerView,
  type ProjectListItem,
  type ProjectSummary,
  type Severity,
  type SignalId,
  type WormResult,
} from "./types.ts";

export const short = (k: string) => k.replace(/^(npm|pypi)\//, "");
const ecoOf = (key: string): Ecosystem => (key.startsWith("pypi/") ? "PyPI" : "npm");
const registry = (key: string) => (key.startsWith("pypi/") ? "PyPI" : "npm");
const installCmd = (key: string) => (key.startsWith("pypi/") ? "pip install" : "npm install");
const SEV: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const SIGNAL_ORDER: SignalId[] = ["malware", "possible_malware", "removed", "takeover", "risky_install_script", "typosquat", "provenance_dropped", "new_install_script", "unpinned_mcp", "fresh_release", "vulnerability"];
const SUSPICIOUS: SignalId[] = ["takeover", "risky_install_script", "typosquat", "provenance_dropped", "new_install_script", "unpinned_mcp", "fresh_release"];
const notFound = (msg: string) => Object.assign(new Error(msg), { statusCode: 404 });

/** Text written by package authors (possibly the attacker): no control or bidi characters, no quote markers, bounded. */
const UNSAFE = new RegExp("[\\u0000-\\u0008\\u000b-\\u001f\\u007f\\u200b-\\u200f\\u2028-\\u202e\\u00ab\\u00bb]", "g");
export const untrusted = (s: string) => String(s ?? "").replace(UNSAFE, "").slice(0, 400);

export interface ProjectRef {
  id: string;
  key: string;
  name: string;
  kind: "app" | "agent-config";
  source: string;
  scanId: string;
  scannedAt: number;
  direct: number;
}

export async function getProject(org: string, projectId: string): Promise<ProjectRef> {
  const [row] = await read(org, Q("project_get"), { projectId });
  if (!row?.project?.id) throw notFound(`No project "${projectId}" in this workspace. Scan a lockfile first.`);
  const p = row.project;
  return { id: p.id, key: p.key, name: p.name, kind: p.kind, source: p.source, scanId: p.latest_scan, scannedAt: p.scanned_at, direct: row.direct };
}

export async function listProjects(org: string): Promise<ProjectListItem[]> {
  return (await read(org, Q("project_list"))).map(({ project: p }) => ({ id: p.id, name: p.name, kind: p.kind, source: p.source, scannedAt: p.scanned_at, verdict: p.verdict ?? "clean" }));
}

// ───────────── the project's own dependency tree (BFS from the project over its own edges) ─────────────
export interface Tree {
  root: string;
  depth: Map<string, number>;
  parent: Map<string, string>;
  nodes: { key: string; name: string; version: string; dev: boolean }[];
  direct: Map<string, boolean>;
}

export async function projectTree(org: string, p: ProjectRef): Promise<Tree> {
  const [nodes, edges, direct] = await Promise.all([
    read(org, Q("tree_nodes"), { scanId: p.scanId }),
    read(org, Q("tree_edges"), { scanId: p.scanId, projectId: p.id }),
    read(org, Q("tree_direct"), { projectId: p.id }),
  ]);
  const adj = new Map<string, string[]>();
  for (const e of edges) adj.set(e.from, [...(adj.get(e.from) ?? []), e.to]);
  const root = `project/${p.id}`;
  const depth = new Map([[root, 0]]);
  const parent = new Map<string, string>();
  const queue: string[] = [];
  const dmap = new Map<string, boolean>();
  for (const d of direct) {
    dmap.set(d.key, !!d.dev);
    if (!depth.has(d.key)) {
      depth.set(d.key, 1);
      parent.set(d.key, root);
      queue.push(d.key);
    }
  }
  for (let i = 0; i < queue.length; i++) {
    const k = queue[i];
    for (const c of adj.get(k) ?? []) {
      if (depth.has(c)) continue;
      depth.set(c, depth.get(k)! + 1);
      parent.set(c, k);
      queue.push(c);
    }
  }
  return { root, depth, parent, nodes: nodes.map((n) => ({ key: n.key, name: n.name, version: n.version, dev: !!n.dev })), direct: dmap };
}

export function pathTo(t: Tree, key: string): string[] {
  const path = [key];
  const seen = new Set([key]);
  let cur = t.parent.get(key);
  while (cur && !seen.has(cur)) {
    path.unshift(cur);
    seen.add(cur);
    cur = t.parent.get(cur);
  }
  return path[0] === t.root ? path : [t.root, ...path];
}

// ───────────── triage: findings, then memory, then learned rules ─────────────
interface Draft {
  id: string;
  version: string;
  signal: SignalId;
  severity: Severity;
  title: string;
  detail: string;
  fix: string;
  path: string[];
  advisories: string[];
  status: FindingStatus;
  note: string | null;
  ruleId: string | null;
}

export const findingId = (projectId: string, versionKey: string, signal: string) => `f-${createHash("sha1").update(`${projectId}|${versionKey}|${signal}`).digest("hex").slice(0, 12)}`;
const day = (ms?: number | null) => (ms ? new Date(ms).toISOString().slice(0, 10) : "earlier");
const via = (path: string[]) => (path.length > 2 ? ` It reaches you through ${path.slice(1, -1).map(short).join(" → ")}.` : " It is a direct dependency.");

export async function triage(org: string, p: ProjectRef, tree: Tree): Promise<{ findings: FindingView[]; verdict: ProjectSummary["verdict"] }> {
  const drafts = new Map<string, Draft>();
  const add = (d: Omit<Draft, "id" | "status" | "note" | "ruleId">) => {
    const id = findingId(p.id, d.version, d.signal);
    if (!drafts.has(id)) drafts.set(id, { ...d, id, status: "open", note: null, ruleId: null });
  };

  // 1. Advisories, each with the shortest route from the project (Cypher), or the project's own tree if that borrows an edge.
  const exposures = await read(org, Q("exposure_paths"), { projectId: p.id, scanId: p.scanId });
  const byVersion = new Map<string, any[]>();
  for (const r of exposures) byVersion.set(r.version, [...(byVersion.get(r.version) ?? []), r]);
  for (const [version, rows] of byVersion) {
    const own = rows.find((r) => r.ownRoute);
    const path: string[] = own ? own.path : pathTo(tree, version);
    const name = short(version);
    const malware = rows.filter((r) => r.kind === "malware");
    const confirmed = malware.filter((r) => r.explicit);
    const vulns = rows.filter((r) => r.kind === "vuln");
    if (confirmed.length) {
      const fixed = confirmed.find((r) => r.fixed)?.fixed;
      add({
        version, signal: "malware", severity: "critical", path, advisories: malware.map((r) => r.advisory),
        title: `${name} is known malware`,
        detail: `${untrusted(confirmed[0].summary)}.${via(path)}`,
        fix: `${fixed ? `Upgrade to ${fixed} or later` : "Remove it or pin the release before the compromise"}, ${version.startsWith("pypi/") ? "rebuild your virtualenv" : "delete node_modules and reinstall"}, and rotate ${registry(version)}, GitHub and cloud tokens on every machine and CI runner that installed it.`,
      });
    } else if (malware.length) {
      add({
        version, signal: "possible_malware", severity: "high", path, advisories: malware.map((r) => r.advisory),
        title: `${name} falls inside a malware advisory's range`,
        detail: `${untrusted(malware[0].summary)}. The advisory matches by version range, which can include clean releases.${via(path)}`,
        fix: "Check the advisory's list of affected versions; if in doubt, move to a release published after it.",
      });
    }
    if (vulns.length) {
      const worst = vulns.map((v) => v.severity as Severity).sort((a, b) => SEV[a] - SEV[b])[0] ?? "medium";
      const fixed = vulns.find((v) => v.fixed)?.fixed;
      add({
        version, signal: "vulnerability", severity: worst, path, advisories: vulns.map((v) => v.advisory),
        title: `${name} has ${vulns.length} known ${vulns.length === 1 ? "vulnerability" : "vulnerabilities"}`,
        detail: `${untrusted(vulns[0].summary)}${vulns.length > 1 ? ` (and ${vulns.length - 1} more)` : ""}.${via(path)}`,
        fix: fixed ? `Upgrade to ${fixed} or later.` : "Check the advisories for a patched release.",
      });
    }
  }

  // 2. Release signals that need no advisory.
  const now = Date.now();
  for (const f of await read(org, Q("release_facts"), { scanId: p.scanId })) {
    const name = `${f.name}@${f.version}`;
    const path = pathTo(tree, f.key);
    if (f.removed && !byVersion.has(f.key)) {
      add({
        version: f.key, signal: "removed", severity: "critical", path, advisories: [],
        title: /-security$/.test(f.version) ? `npm took ${f.name} down for security reasons` : `${name} was removed from ${registry(f.key)}`,
        detail: /-security$/.test(f.version)
          ? `${name} is npm's security placeholder: npm removes a package that shipped malware and leaves this empty package in its place.${via(path)}`
          : `Your lockfile pins a version that ${registry(f.key)} no longer serves. Registries delete releases that shipped malware.${via(path)}`,
        fix: "Don't reinstall from this lockfile. Move to a current release and check the machines that installed this one.",
      });
    }
    const pubs: { key: string; login: string; kind: string }[] = f.pubs ?? [];
    const prevPubs: { key: string; login: string; kind: string }[] = f.prevPubs ?? [];
    const newScript = !!f.script && !!f.prevKey && !f.prevScript;
    const allCi = [...pubs, ...prevPubs].every((x) => x.kind === "workflow");
    const changed = pubs.length > 0 && prevPubs.length > 0 && !allCi && !pubs.some((x) => prevPubs.some((y) => y.key === x.key));
    const scripts = (f.scripts ?? []).join(", ") || "an install script";
    if (newScript && changed) {
      add({
        version: f.key, signal: "takeover", severity: "high", path, advisories: [],
        title: `${name} added an install script under a new publisher`,
        detail: `${pubs.map((x) => x.login).join(", ")} published this release; ${prevPubs.map((x) => x.login).join(", ")} published ${short(f.prevKey)}. It also adds ${scripts}, which runs on ${installCmd(f.key)}. That is what an account takeover looks like.`,
        fix: `Pin ${short(f.prevKey)} and read the install script before upgrading.`,
      });
    } else if (newScript) {
      add({
        version: f.key, signal: "new_install_script", severity: "medium", path, advisories: [],
        title: `${name} added an install script`,
        detail: `${scripts} appears in this release but not in ${short(f.prevKey)}. Install scripts run with your permissions on ${installCmd(f.key)}.`,
        fix: "Review the script, or install with --ignore-scripts.",
      });
    }
    if (f.scriptFlags?.length) {
      add({
        version: f.key, signal: "risky_install_script", severity: newScript ? "critical" : "high", path, advisories: [],
        title: `${name} runs a risky install script`,
        detail: `On ${installCmd(f.key)} it runs (untrusted text from the package):\n«${untrusted(f.scriptText ?? scripts)}»\nIt ${f.scriptFlags.join(", ")}.`,
        fix: "Install with --ignore-scripts, read the script, and pin a version without it if you can't verify it.",
      });
    }
    if (f.typosquatOf) {
      add({
        version: f.key, signal: "typosquat", severity: "high", path, advisories: [],
        title: `${f.name} looks like a typosquat of ${f.typosquatOf}`,
        detail: `The name is one keystroke from ${f.typosquatOf}, one of ${registry(f.key)}'s most downloaded packages, but ${f.name} gets ${f.downloads ? Number(f.downloads).toLocaleString("en-US") : "almost no"} downloads a month.`,
        fix: `Check that you meant ${f.name}, not ${f.typosquatOf}. If it was a typo, replace it and check what it ran on install.`,
      });
    }
    if (f.prevKey && f.prevProvenance === true && f.provenance === false && !f.removed) {
      add({
        version: f.key, signal: "provenance_dropped", severity: "high", path, advisories: [],
        title: `${name} lost its build provenance`,
        detail: `${short(f.prevKey)} was published from CI with a signed attestation; this release wasn't. Publishing straight from an account instead of CI is how the axios compromise shipped.`,
        fix: `Pin ${short(f.prevKey)} until the maintainers confirm this release.`,
      });
    }
    const at = f.published ? Date.parse(f.published) : NaN;
    if (!Number.isNaN(at) && now - at >= 0 && now - at < 72 * 3600_000) {
      add({
        version: f.key, signal: "fresh_release", severity: String(f.version).includes("-") ? "low" : "medium", path, advisories: [],
        title: `${name} was published ${Math.max(1, Math.round((now - at) / 3600_000))} hours ago`,
        detail: "Most worm releases are caught within hours to days of publishing.",
        fix: "Wait for a cooldown (for example pnpm minimumReleaseAge) before adopting it.",
      });
    }
  }

  // 3. The AI tools' own supply chain.
  for (const s of await read(org, Q("mcp_exposure"), { projectId: p.id })) {
    if (s.pinned || !s.packageKey) continue;
    add({
      version: s.packageKey, signal: "unpinned_mcp", severity: "medium", path: pathTo(tree, s.packageKey), advisories: [],
      title: `MCP server "${s.name}" runs whatever version is newest`,
      detail: `${s.client} starts it with \`${untrusted(s.command)}\`. Without a pinned version, a compromised release would run inside your AI tool on its next launch.`,
      fix: `Pin it to ${short(s.packageKey)} in the config.`,
    });
  }

  // 4. Memory: earlier human verdicts on the same versions, then active learned rules.
  const keys = [...new Set([...drafts.values()].map((d) => d.version))];
  const prior = keys.length ? await read(org, Q("verdicts_prior"), { keys }) : [];
  const rules = await read(org, Q("rules_active"));
  for (const d of drafts.values()) {
    const earlier = prior.find((v) => v.version === d.version && v.signal === d.signal && v.id !== d.id);
    const word = earlier?.verdict === "dismissed" ? "not a threat" : "an accepted risk";
    if (earlier && earlier.verdict !== "confirmed" && COMPROMISE.includes(d.signal)) {
      d.note = `Marked ${word} in another project on ${day(earlier.at)}${earlier.note ? ` ("${untrusted(earlier.note)}")` : ""}. Compromise findings are never skipped automatically; decide again for this project.`;
    } else if (earlier && earlier.verdict !== "confirmed") {
      d.status = "skipped";
      d.note = `Skipped: marked ${word} on ${day(earlier.at)}${earlier.note ? ` ("${untrusted(earlier.note)}")` : ""}.`;
    } else if (earlier) {
      d.note = `Confirmed as a real threat in another project on ${day(earlier.at)}.`;
    }
    const rule = rules.find((r) => r.when === d.signal);
    if (rule && !COMPROMISE.includes(d.signal)) {
      d.ruleId = rule.id;
      if (rule.then === "escalate" && d.status !== "skipped") {
        d.severity = "critical";
        d.note = `Escalated by a learned rule (${d.signal.replace(/_/g, " ")} → escalate).`;
      } else if (rule.then === "skip" && d.status === "open") {
        d.status = "skipped";
        d.note = `Skipped by a learned rule (${d.signal.replace(/_/g, " ")} → skip).`;
      }
    }
  }

  const rows = [...drafts.values()].map((d) => ({ ...d, ecosystem: ecoOf(d.version) }));
  await run(org, Q("findings_upsert"), { projectId: p.id, scanId: p.scanId, rows });
  const ev = rows.flatMap((d) => d.advisories.map((a) => ({ id: d.id, advisory: a })));
  if (ev.length) await run(org, Q("findings_evidence"), { rows: ev });
  const findings = await loadFindings(org, p);
  const verdict = verdictOf(findings);
  await run(org, Q("project_set_verdict"), { projectId: p.id, verdict });
  return { findings, verdict };
}

export async function loadFindings(org: string, p: ProjectRef): Promise<FindingView[]> {
  const rows = await read(org, Q("findings_list"), { projectId: p.id, scanId: p.scanId });
  return rows
    .map((r): FindingView => ({
      id: r.finding.id,
      versionKey: r.versionKey,
      name: r.name,
      version: r.version,
      ecosystem: r.finding.ecosystem ?? ecoOf(r.versionKey),
      signal: r.finding.signal,
      severity: r.finding.severity,
      title: r.finding.title,
      detail: r.finding.detail,
      path: r.finding.path ?? [],
      advisories: (r.advisories ?? []).filter((a: AdvisoryRef | null) => a?.id),
      status: r.finding.status,
      statusNote: r.finding.status_note ?? undefined,
      fix: r.finding.fix ?? undefined,
    }))
    .sort(
      (a, b) =>
        Number(a.status === "skipped") - Number(b.status === "skipped") ||
        SEV[a.severity] - SEV[b.severity] ||
        SIGNAL_ORDER.indexOf(a.signal) - SIGNAL_ORDER.indexOf(b.signal) ||
        a.name.localeCompare(b.name),
    );
}

export function verdictOf(findings: FindingView[]): ProjectSummary["verdict"] {
  const live = findings.filter((f) => f.status === "open" || f.status === "confirmed");
  if (live.some((f) => COMPROMISE.includes(f.signal))) return "compromised";
  if (live.some((f) => SUSPICIOUS.includes(f.signal) || (f.signal === "vulnerability" && SEV[f.severity] <= SEV.high))) return "suspicious";
  return "clean";
}

// ───────────── accounts: who could poison how much of the tree ─────────────
export async function accounts(org: string, p: ProjectRef, limit = 10, flagged?: Set<string>): Promise<AccountView[]> {
  const [[counts], rows] = await Promise.all([read(org, Q("project_counts"), { scanId: p.scanId }), read(org, Q("accounts_reach"), { scanId: p.scanId, limit })]);
  const total = Math.max(1, counts?.packages ?? 1);
  const bad = flagged ?? new Set((await loadFindings(org, p)).filter((f) => f.signal !== "vulnerability" && f.status !== "skipped").map((f) => f.versionKey));
  return rows.map((r) => ({ key: r.key, login: r.login, kind: r.kind, versions: r.versions, share: r.versions / total, weight: r.weight, flagged: (r.keys as string[]).some((k) => bad.has(k)) }));
}

// ───────────── worm simulation ─────────────
export async function simulateWorm(org: string, p: ProjectRef, login: string, waves = 4): Promise<WormResult> {
  const [start] = await read(org, Q("account_resolve"), { scanId: p.scanId, login });
  if (!start) throw notFound(`"${login}" doesn't maintain anything in this project.`);
  const [counts] = await read(org, Q("project_counts"), { scanId: p.scanId });
  const total = Math.max(1, counts?.packages ?? 1);
  const compromised = new Set<string>([start.key]);
  const poisoned = new Set<string>();
  const out: WormResult = { start: start.login, waves: [], poisonedShare: 0, compromisedAccounts: 0, totalVersions: total };
  let frontier = [start.key];
  for (let w = 1; w <= waves && frontier.length; w++) {
    const [row] = await read(org, Q("worm_wave"), { scanId: p.scanId, projectId: p.id, compromised: [...compromised] });
    const fresh = ((row?.poisoned ?? []) as string[]).filter((k) => !poisoned.has(k));
    fresh.forEach((k) => poisoned.add(k));
    out.waves.push({ wave: w, accounts: frontier.map((k) => k.replace(/^[^/]+\//, "")), poisoned: fresh });
    frontier = ((row?.nextWave ?? []) as string[]).filter((k) => !compromised.has(k));
    frontier.forEach((k) => compromised.add(k));
  }
  out.poisonedShare = poisoned.size / total;
  out.compromisedAccounts = out.waves.reduce((n, w) => n + w.accounts.length, 0);
  return out;
}

// ───────────── dependency graph for the UI ─────────────
export async function dependencyGraph(org: string, p: ProjectRef): Promise<DependencyGraph> {
  const [tree, findings] = await Promise.all([projectTree(org, p), loadFindings(org, p)]);
  const risk = new Map<string, GraphNode["risk"]>();
  const rank = { malware: 0, suspicious: 1, vuln: 2 } as const;
  for (const f of findings) {
    if (f.status !== "open" && f.status !== "confirmed") continue;
    const r = COMPROMISE.includes(f.signal) ? "malware" : f.signal === "vulnerability" ? "vuln" : "suspicious";
    const cur = risk.get(f.versionKey);
    if (!cur || rank[r] < rank[cur]) risk.set(f.versionKey, r);
  }
  const nodes: GraphNode[] = [{ key: tree.root, name: p.name, version: "", depth: 0, risk: null, direct: false, dev: false }];
  for (const n of tree.nodes) if (tree.depth.has(n.key)) nodes.push({ ...n, depth: tree.depth.get(n.key)!, risk: risk.get(n.key) ?? null, direct: tree.direct.has(n.key) });
  const infected = new Map<string, { from: string; to: string }>();
  for (const [k, r] of risk) {
    if (r === "vuln" || !tree.depth.has(k)) continue;
    for (let cur = k; cur !== tree.root && tree.parent.has(cur); cur = tree.parent.get(cur)!) infected.set(cur, { from: cur, to: tree.parent.get(cur)! });
  }
  return { root: tree.root, rootName: p.name, nodes, edges: [...tree.parent].map(([from, to]) => ({ from, to })), infected: [...infected.values()] };
}

// ───────────── project summary ─────────────
export async function summary(org: string, projectId: string): Promise<ProjectSummary> {
  const p = await getProject(org, projectId);
  const [findings, [counts], tree, mcp] = await Promise.all([
    loadFindings(org, p),
    read(org, Q("project_counts"), { scanId: p.scanId }),
    read(org, Q("tree_edges"), { scanId: p.scanId, projectId: p.id }),
    read(org, Q("mcp_exposure"), { projectId: p.id }),
  ]);
  const flagged = new Set(findings.filter((f) => f.signal !== "vulnerability" && f.status !== "skipped").map((f) => f.versionKey));
  return {
    id: p.id,
    name: p.name,
    kind: p.kind,
    source: p.source,
    scanId: p.scanId,
    scannedAt: p.scannedAt,
    counts: { packages: counts?.packages ?? 0, direct: p.direct, accounts: counts?.accounts ?? 0, advisories: counts?.advisories ?? 0, edges: tree.length },
    verdict: verdictOf(findings),
    findings,
    topAccounts: await accounts(org, p, 10, flagged),
    mcpServers: mcp.map((s): McpServerView => ({ name: s.name, client: s.client, command: s.command, pinned: !!s.pinned, packageKey: s.packageKey ?? null, advisories: (s.advisories ?? []).filter(Boolean) })),
  };
}
