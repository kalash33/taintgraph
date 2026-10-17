import { createHash } from "node:crypto";
import { config } from "../config.ts";
import { redis } from "../db.ts";
import type { Ecosystem } from "../types.ts";

// Public data sources, cached in FalkorDB's own Redis keyspace. All of them are free and need no API key.
const HOUR = 3600;
const UA = { "user-agent": config.userAgent };

async function cached<T>(url: string, o: { ttl: number; method?: string; body?: unknown; allow404?: boolean; fresh?: boolean }): Promise<T | null> {
  const body = o.body === undefined ? undefined : JSON.stringify(o.body);
  const key = "tg:cache:" + createHash("sha1").update(`${o.method ?? "GET"} ${url} ${body ?? ""}`).digest("hex");
  const r = await redis();
  if (!o.fresh) {
    const hit = await r.get(key);
    if (hit !== null) return JSON.parse(hit);
  }
  let last: any;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const res = await fetch(url, {
        method: o.method ?? "GET",
        headers: { ...UA, accept: "application/json", ...(body ? { "content-type": "application/json" } : {}) },
        body,
        signal: AbortSignal.timeout(25_000),
      });
      if (res.status === 404 && o.allow404) {
        await r.set(key, "null", { EX: o.ttl });
        return null;
      }
      if (!res.ok) {
        last = new Error(`${res.status} from ${new URL(url).host}`);
        if (res.status !== 429 && res.status < 500) break; // client errors don't get better with retries
      } else {
        const data = (await res.json()) as T;
        await r.set(key, JSON.stringify(data), { EX: o.ttl });
        return data;
      }
    } catch (e) {
      last = e;
    }
    await new Promise((res) => setTimeout(res, 500 * 2 ** attempt));
  }
  throw last;
}

const enc = (name: string) => (name.startsWith("@") ? "@" + encodeURIComponent(name.slice(1)) : encodeURIComponent(name));

// ───────────── OSV.dev: malware and vulnerability advisories ─────────────
export interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  published?: string;
  affected?: { package?: { name: string; ecosystem: string }; versions?: string[]; ranges?: { type: string; events: Record<string, string>[] }[] }[];
  database_specific?: { severity?: string; cwe_ids?: string[] };
}

export async function osvBatch(pkgs: { name: string; version: string; ecosystem: Ecosystem }[], fresh = false): Promise<string[][]> {
  const out: string[][] = [];
  for (let i = 0; i < pkgs.length; i += 1000) {
    const chunk = pkgs.slice(i, i + 1000);
    const res = await cached<{ results: { vulns?: { id: string }[] }[] }>("https://api.osv.dev/v1/querybatch", {
      method: "POST",
      ttl: HOUR,
      fresh,
      body: { queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })) },
    });
    for (const r of res?.results ?? []) out.push((r.vulns ?? []).map((v) => v.id));
  }
  return out;
}

export const osvVuln = (id: string) => cached<OsvVuln>(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, { ttl: 24 * HOUR, allow404: true });

/** Loose version comparison: numeric where both parts are numbers (semver and most PEP 440 releases). */
export function compareVersions(a: string, b: string): number {
  const pa = a.split(/[.+-]/);
  const pb = b.split(/[.+-]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? "0";
    const y = pb[i] ?? "0";
    const nx = Number(x);
    const ny = Number(y);
    if (!Number.isNaN(nx) && !Number.isNaN(ny)) {
      if (nx !== ny) return nx - ny;
    } else if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

const sameName = (a: string, b: string) => a.toLowerCase().replace(/[-_.]+/g, "-") === b.toLowerCase().replace(/[-_.]+/g, "-");

export interface Classified {
  id: string;
  kind: "malware" | "vuln";
  explicit: boolean; // malware confirmed by an explicit version list (MAL-), not just a range
  severity: "critical" | "high" | "medium" | "low";
  summary: string;
  published: string;
  url: string;
  fixed: string | null; // the fix for the range that contains this version
}

/**
 * OSV range matching over-includes for malware (the TanStack GHSA range also matches clean 1.169.6), so only an
 * explicit MAL- version list confirms malware; a range-only match is "possible malware".
 */
/** Advisory wording that describes shipped malware rather than a bug (not "malicious users" or "malicious input"). */
export const MALWARE_TEXT = /^(malicious|malware)\b|\bmalicious (code|software|package|version|release|payload)|\bmalware\b|\bcrypto ?(currency )?miner|\bcredential stealer|\bbackdoor(ed)?\b/i;

export function classifyAdvisory(v: OsvVuln, name: string, version: string): Classified | null {
  const affected = (v.affected ?? []).filter((a) => a.package?.name && sameName(a.package.name, name));
  const listed = affected.flatMap((a) => a.versions ?? []);
  const isMal = v.id.startsWith("MAL-");
  if (isMal && listed.length && !listed.includes(version)) return null;
  const malware = isMal || (v.database_specific?.cwe_ids ?? []).includes("CWE-506") || MALWARE_TEXT.test(v.summary ?? "");
  let fixed: string | null = null;
  for (const a of affected)
    for (const r of a.ranges ?? []) {
      if (r.type === "GIT") continue;
      let introduced = "0";
      for (const ev of r.events) {
        if (ev.introduced) introduced = ev.introduced;
        if (ev.fixed && compareVersions(introduced, version) <= 0 && compareVersions(version, ev.fixed) < 0) fixed = ev.fixed;
      }
    }
  const sev = (v.database_specific?.severity ?? "").toLowerCase();
  return {
    id: v.id,
    kind: malware ? "malware" : "vuln",
    explicit: isMal,
    severity: malware ? "critical" : sev === "critical" ? "critical" : sev === "high" ? "high" : sev === "low" ? "low" : "medium",
    summary: (v.summary || v.details?.split("\n")[0] || v.id).slice(0, 300),
    published: v.published ?? "",
    url: v.id.startsWith("GHSA-") ? `https://github.com/advisories/${v.id}` : `https://osv.dev/vulnerability/${v.id}`,
    fixed,
  };
}

// ───────────── npm registry ─────────────
export interface NpmVersionDoc {
  _npmUser?: { name: string; trustedPublisher?: unknown };
  maintainers?: { name: string }[];
  scripts?: Record<string, string>;
  dist?: { attestations?: unknown };
  description?: string;
}

export const npmVersion = (name: string, version: string) =>
  cached<NpmVersionDoc>(`https://registry.npmjs.org/${enc(name)}/${encodeURIComponent(version)}`, { ttl: 24 * HOUR, allow404: true });

export const INSTALL_HOOKS = ["preinstall", "install", "postinstall"];
export const installHooks = (scripts?: Record<string, string>) => Object.fromEntries(INSTALL_HOOKS.filter((h) => scripts?.[h]).map((h) => [h, scripts![h]]));

export interface NpmHistory {
  time: Record<string, string>;
  versions: Record<string, { user?: string; trusted?: boolean; hooks: Record<string, string>; attested: boolean }>;
  maintainers: string[];
}

/** Release history for one package, slimmed before caching. Packuments over 15 MB (e.g. react's canaries) are skipped. */
export async function npmHistory(name: string): Promise<NpmHistory | null> {
  const key = `tg:cache:history:${name}`;
  const r = await redis();
  const hit = await r.get(key);
  if (hit !== null) return JSON.parse(hit);
  const res = await fetch(`https://registry.npmjs.org/${enc(name)}`, { headers: UA, signal: AbortSignal.timeout(30_000) });
  if (res.status === 404 || Number(res.headers.get("content-length") ?? 0) > 15 * 1024 * 1024) {
    await res.body?.cancel();
    await r.set(key, "null", { EX: HOUR });
    return null;
  }
  if (!res.ok) throw new Error(`${res.status} from npm for ${name}`);
  const full: any = await res.json();
  const slim: NpmHistory = { time: full.time ?? {}, versions: {}, maintainers: (full.maintainers ?? []).map((m: any) => m.name) };
  for (const [v, d] of Object.entries<any>(full.versions ?? {})) {
    slim.versions[v] = { user: d._npmUser?.name, trusted: !!d._npmUser?.trustedPublisher, hooks: installHooks(d.scripts), attested: !!d.dist?.attestations };
  }
  await r.set(key, JSON.stringify(slim), { EX: HOUR });
  return slim;
}

export async function npmLatest(name: string): Promise<string | null> {
  return (await cached<{ version?: string }>(`https://registry.npmjs.org/${enc(name)}/latest`, { ttl: HOUR, allow404: true }))?.version ?? null;
}

// ───────────── PyPI ─────────────
export interface PypiProject {
  latest: string;
  organization: string | null;
  owners: string[];
  releases: Record<string, { time: string | null; yanked: boolean }>;
}

export async function pypiProject(name: string): Promise<PypiProject | null> {
  const key = `tg:cache:pypi:${name}`;
  const r = await redis();
  const hit = await r.get(key);
  if (hit !== null) return JSON.parse(hit);
  const res = await fetch(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`, { headers: UA, signal: AbortSignal.timeout(30_000) });
  if (res.status === 404) {
    await r.set(key, "null", { EX: HOUR });
    return null;
  }
  if (!res.ok) throw new Error(`${res.status} from PyPI for ${name}`);
  const full: any = await res.json();
  const releases: PypiProject["releases"] = {};
  for (const [v, files] of Object.entries<any[]>(full.releases ?? {})) {
    const times = files.map((f) => f.upload_time_iso_8601).filter(Boolean).sort();
    releases[v] = { time: times[0] ?? null, yanked: files.length > 0 && files.every((f) => f.yanked) };
  }
  const slim: PypiProject = {
    latest: full.info?.version ?? "",
    organization: full.ownership?.organization ?? null,
    owners: (full.ownership?.roles ?? []).map((x: any) => x.user).filter(Boolean),
    releases,
  };
  await r.set(key, JSON.stringify(slim), { EX: HOUR });
  return slim;
}

// ───────────── deps.dev: publish dates, SLSA provenance, dependency graphs ─────────────
export interface DepsDevVersion {
  publishedAt?: string;
  slsaProvenances?: { sourceRepository?: string }[];
}

export async function depsDevBatch(pkgs: { name: string; version: string; ecosystem: Ecosystem }[]): Promise<Map<string, DepsDevVersion>> {
  const out = new Map<string, DepsDevVersion>();
  for (let i = 0; i < pkgs.length; i += 1000) {
    const chunk = pkgs.slice(i, i + 1000);
    let pageToken: string | undefined;
    do {
      const res: any = await cached("https://api.deps.dev/v3alpha/versionbatch", {
        method: "POST",
        ttl: 24 * HOUR,
        body: { requests: chunk.map((p) => ({ versionKey: { system: p.ecosystem === "PyPI" ? "PYPI" : "NPM", name: p.name, version: p.version } })), pageToken },
      });
      for (const r of res?.responses ?? []) {
        const k = r.request.versionKey;
        if (r.version) out.set(`${k.system === "PYPI" ? "pypi" : "npm"}:${k.name.toLowerCase()}@${k.version}`, r.version);
      }
      pageToken = res?.nextPageToken || undefined;
    } while (pageToken);
  }
  return out;
}

export const depsDevKey = (eco: Ecosystem, name: string, version: string) => `${eco === "PyPI" ? "pypi" : "npm"}:${name.toLowerCase()}@${version}`;

export const depsDevDependencies = (eco: Ecosystem, name: string, version: string) =>
  cached<{ nodes: { versionKey: { name: string; version: string } }[]; edges: { fromNode: number; toNode: number }[] }>(
    `https://api.deps.dev/v3/systems/${eco === "PyPI" ? "pypi" : "npm"}/packages/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}:dependencies`,
    { ttl: 24 * HOUR, allow404: true },
  );

// ───────────── ecosyste.ms: reach (dependents, downloads) and top packages ─────────────
const purl = (eco: Ecosystem, name: string) => (eco === "PyPI" ? `pkg:pypi/${name}` : `pkg:npm/${name.startsWith("@") ? "%40" + name.slice(1) : name}`);
const normKey = (eco: Ecosystem, n: string) => (eco === "PyPI" ? n.toLowerCase().replace(/[-_.]+/g, "-") : n);

/** Names the index doesn't know get zeros (obscure); names from a chunk that failed are left out (unknown). */
export async function reach(eco: Ecosystem, names: string[]): Promise<Map<string, { dependents: number; downloads: number }>> {
  const out = new Map<string, { dependents: number; downloads: number }>();
  for (let i = 0; i < names.length; i += 100) {
    const chunk = names.slice(i, i + 100);
    try {
      const rows = await cached<any[]>("https://packages.ecosyste.ms/api/v1/packages/bulk_lookup", { method: "POST", ttl: 24 * HOUR, body: { purls: chunk.map((n) => purl(eco, n)) } });
      for (const n of chunk) out.set(normKey(eco, n), { dependents: 0, downloads: 0 });
      for (const p of rows ?? []) out.set(normKey(eco, p.name), { dependents: p.dependent_packages_count ?? 0, downloads: p.downloads ?? 0 });
    } catch (e: any) {
      console.warn(`[ecosyste.ms] reach lookup failed for ${chunk.length} names:`, e.message);
    }
  }
  return out;
}

const topMemo = new Map<Ecosystem, Promise<Map<string, number>>>();

/** The 2,000 most-downloaded packages (name -> monthly downloads). Kept slim in Redis and in memory. */
export function topPackages(eco: Ecosystem): Promise<Map<string, number>> {
  if (!topMemo.has(eco)) {
    const p = (async () => {
      const r = await redis();
      const key = `tg:cache:top:${eco}`;
      const hit = await r.get(key);
      if (hit) return new Map<string, number>(JSON.parse(hit));
      const fresh = await fetchTopPackages(eco);
      if (fresh.size) await r.set(key, JSON.stringify([...fresh]), { EX: 7 * 24 * HOUR });
      return fresh;
    })();
    topMemo.set(eco, p);
    p.then((m) => !m.size && topMemo.delete(eco)).catch(() => topMemo.delete(eco));
  }
  return topMemo.get(eco)!;
}

async function fetchTopPackages(eco: Ecosystem): Promise<Map<string, number>> {
  const out = new Map<string, number>();
  for (const page of [1, 2]) {
    try {
      const rows = await cached<any[]>(
        `https://packages.ecosyste.ms/api/v1/registries/${eco === "PyPI" ? "pypi.org" : "npmjs.org"}/packages?sort=downloads&order=desc&per_page=1000&page=${page}`,
        { ttl: 7 * 24 * HOUR },
      );
      for (const p of rows ?? []) if (p.name && p.downloads) out.set(normKey(eco, p.name), p.downloads);
    } catch (e: any) {
      console.warn("[ecosyste.ms] top packages unavailable; typosquat check skipped:", e.message);
      break;
    }
  }
  return out;
}

// ───────────── GitHub: fetch a public repo's lockfile ─────────────
