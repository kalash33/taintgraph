import { read } from "./db.ts";
import { Q } from "./queries.ts";
import { getProject, loadFindings } from "./analysis.ts";
import type { ScanChanges } from "./types.ts";

// Every scan is kept, so a rescan can say what moved: new packages, removed ones, version changes, and which of the
// new versions are flagged. That's the moment a compromise usually arrives: a lockfile update.

export async function scanChanges(org: string, projectId: string): Promise<ScanChanges> {
  const p = await getProject(org, projectId);
  const scans = await read(org, Q("scan_history"), { projectId: p.id });
  if (scans.length < 2) return { since: null, added: [], removed: [], changed: [], newlyFlagged: [] };
  const [cur, prev] = await Promise.all(scans.map((s) => read(org, Q("scan_versions"), { scanId: s.id })));
  const byName = (rows: any[]) => {
    const m = new Map<string, Set<string>>();
    for (const r of rows) m.set(r.name, (m.get(r.name) ?? new Set()).add(r.version));
    return m;
  };
  const now = byName(cur);
  const before = byName(prev);
  const added: ScanChanges["added"] = [];
  const removed: ScanChanges["removed"] = [];
  const changed: ScanChanges["changed"] = [];
  for (const [name, vs] of now) {
    const old = before.get(name);
    if (!old) for (const version of vs) added.push({ name, version });
    else {
      const to = [...vs].filter((v) => !old.has(v));
      const from = [...old].filter((v) => !vs.has(v));
      if (to.length || from.length) changed.push({ name, from, to });
    }
  }
  for (const [name, vs] of before) if (!now.has(name)) for (const version of vs) removed.push({ name, version });
  const prevKeys = new Set(prev.map((r) => r.key as string));
  const newlyFlagged = (await loadFindings(org, p))
    .filter((f) => (f.status === "open" || f.status === "confirmed") && !prevKeys.has(f.versionKey))
    .map((f) => ({ findingId: f.id, versionKey: f.versionKey, name: f.name, version: f.version, signal: f.signal, severity: f.severity, title: f.title }));
  const sort = <T extends { name: string }>(a: T[]) => a.sort((x, y) => x.name.localeCompare(y.name));
  return { since: scans[1].at, added: sort(added), removed: sort(removed), changed: sort(changed), newlyFlagged };
}
