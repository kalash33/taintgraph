import { read } from "./db.ts";
import { Q } from "./queries.ts";
import { getProject, loadFindings, projectTree, untrusted } from "./analysis.ts";
import { compareVersions, osvBatch } from "./ingest/feeds.ts";
import { COMPROMISE, type Ecosystem, type FindingView, type FixItem, type FixPlan, type Severity, type SignalId } from "./types.ts";

// The fix plan: for every open compromise, tampering signal and high or critical CVE, a version to move to.
// Targets come from the graph (the version that fixes every advisory, or the previous release on the same line when
// a malicious release has no fix) and are re-checked against OSV.dev, so the plan never recommends another bad version.

const TAMPERING: SignalId[] = ["takeover", "risky_install_script", "new_install_script", "provenance_dropped"];
const SEV: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const major = (v: string) => v.split(/[.+-]/)[0];

function inScope(f: FindingView) {
  if (f.status !== "open" && f.status !== "confirmed") return false;
  return COMPROMISE.includes(f.signal) || TAMPERING.includes(f.signal) || f.signal === "typosquat" || (f.signal === "vulnerability" && SEV[f.severity] <= SEV.high);
}

export async function fixPlan(org: string, projectId: string): Promise<FixPlan> {
  const p = await getProject(org, projectId);
  const [findings, tree] = await Promise.all([loadFindings(org, p), projectTree(org, p)]);
  const wanted = findings.filter(inScope);
  const keys = [...new Set(wanted.map((f) => f.versionKey))];
  const rows = keys.length ? await read(org, Q("fix_candidates"), { keys }) : [];
  const facts = new Map(rows.map((r) => [r.key as string, r]));
  const dev = new Map(tree.nodes.map((n) => [n.key, n.dev]));
  const versionsOf = new Map<string, number>();
  for (const n of tree.nodes) versionsOf.set(n.name, (versionsOf.get(n.name) ?? 0) + 1);

  // One item per flagged version, driven by its most serious finding.
  const items: FixItem[] = [];
  const alternatives = new Map<string, string>(); // version key -> the forward fix, when the plan goes back to the previous release
  for (const key of keys) {
    const fs = wanted.filter((f) => f.versionKey === key).sort((a, b) => SEV[a.severity] - SEV[b.severity]);
    const top = fs.find((f) => COMPROMISE.includes(f.signal)) ?? fs.find((f) => TAMPERING.includes(f.signal)) ?? fs.find((f) => f.signal === "typosquat") ?? fs[0];
    const r = facts.get(key);
    const from = top.version;
    const fixed = ((r?.fixed ?? []) as (string | null)[]).filter((x): x is string => !!x).sort(compareVersions);
    const fixAll = fixed.at(-1) ?? null;
    const prev = r?.prev && !r.prevRemoved ? (r.prev as string) : null;
    const squat = fs.find((f) => f.signal === "typosquat");
    const base = { name: top.name, ecosystem: top.ecosystem as Ecosystem, from, why: top.signal, severity: top.severity, findingIds: fs.map((f) => f.id), direct: tree.direct.has(key), dev: dev.get(key) ?? false };

    const lookalike = r?.typosquatOf as string | undefined;
    if (top.signal === "typosquat" || ((squat || lookalike) && COMPROMISE.includes(top.signal))) {
      const note = lookalike ? `${top.name} imitates ${lookalike}. Remove it, install ${lookalike} if that's what you meant, and check what it ran on install.` : untrusted((squat ?? top).fix ?? `Remove ${top.name}.`);
      items.push({ ...base, to: null, action: "remove", majorChange: false, check: "unchecked", note });
      continue;
    }
    // A malicious or tampered release: go back to the previous release, unless OSV shows the fix is cleaner (below).
    const backward = (COMPROMISE.includes(top.signal) || TAMPERING.includes(top.signal)) && !!prev;
    const to = backward ? prev : fixAll;
    if (backward && fixAll && fixAll !== prev) alternatives.set(key, fixAll);
    items.push({
      ...base,
      to,
      action: to ? (backward ? "pin_previous" : "upgrade") : COMPROMISE.includes(top.signal) || TAMPERING.includes(top.signal) ? "remove" : "no_fix",
      majorChange: !!to && major(to) !== major(from),
      check: "unchecked",
      note: !to
        ? COMPROMISE.includes(top.signal)
          ? "No clean release is known yet. Remove it or pin an older version you have reviewed."
          : "No fixed version has been published yet."
        : backward
          ? `The release before ${from}.`
          : fixed.length > 1
            ? `Fixes all ${fixed.length} advisories on ${from}.`
            : `Fixes the advisory on ${from}.`,
    });
  }

  // Re-check every target against OSV.dev; never recommend a version that is itself named in a malware advisory.
  const targets = items.filter((i) => i.to);
  if (targets.length) {
    try {
      const keyOf = (i: FixItem) => `${i.ecosystem === "PyPI" ? "pypi" : "npm"}/${i.name}@${i.from}`;
      const alts = targets.filter((i) => alternatives.has(keyOf(i)));
      const ids = await osvBatch([...targets, ...alts].map((i, n) => ({ name: i.name, version: n < targets.length ? i.to! : alternatives.get(keyOf(i))!, ecosystem: i.ecosystem })));
      // Going back only wins if the previous release is clean; otherwise take the forward fix when that one is clean.
      alts.forEach((i, n) => {
        const back = ids[targets.indexOf(i)] ?? [];
        const fwd = ids[targets.length + n] ?? [];
        if (back.length && !fwd.length) {
          const to = alternatives.get(keyOf(i))!;
          ids[targets.indexOf(i)] = fwd;
          i.to = to;
          i.action = "upgrade";
          i.majorChange = major(to) !== major(i.from);
          i.note = `Moves past ${i.from} to the release that fixes its advisories; the release before it has known vulnerabilities.`;
        }
      });
      targets.forEach((i, n) => {
        const found = ids[n] ?? [];
        if (found.some((id) => id.startsWith("MAL-"))) {
          i.note = `${i.to} is itself named in a malware advisory; pin an older release you have reviewed.`;
          i.to = null;
          i.action = "remove";
          i.check = "unchecked";
        } else i.check = found.length ? "has_vulnerabilities" : "clean";
        if (i.check === "has_vulnerabilities") i.note += ` ${found.length} lower-severity advisor${found.length === 1 ? "y" : "ies"} still apply to ${i.to}.`;
      });
    } catch {
      // OSV unreachable: the plan is still useful, the targets are just unchecked.
    }
  }
  items.sort((a, b) => Number(COMPROMISE.includes(b.why)) - Number(COMPROMISE.includes(a.why)) || SEV[a.severity] - SEV[b.severity] || a.name.localeCompare(b.name));

  // Snippets. Packages installed in more than one version are overridden per version so the others aren't touched.
  const keyFor = (i: FixItem) => ((versionsOf.get(i.name) ?? 1) > 1 ? `${i.name}@${i.from}` : i.name);
  const npmItems = items.filter((i) => i.ecosystem === "npm" && i.to);
  const pyItems = items.filter((i) => i.ecosystem === "PyPI" && i.to);
  // Direct dependencies are changed in the manifest; npm rejects an override that conflicts with one (EOVERRIDE).
  const transitive = npmItems.filter((i) => !i.direct);
  const overrides = Object.fromEntries(transitive.map((i) => [keyFor(i), i.to!]));
  const npm = npmItems.length
    ? {
        overrides,
        pnpmOverrides: overrides,
        resolutions: Object.fromEntries(transitive.map((i) => [i.name, i.to!])),
        commands: [
          ...npmItems.filter((i) => i.direct).map((i) => `npm install ${i.dev ? "--save-dev " : ""}${i.name}@${i.to}`),
          ...(transitive.length ? ["# then add the overrides block to package.json and run: npm install"] : []),
          ...items.filter((i) => i.ecosystem === "npm" && i.action === "remove").map((i) => `npm uninstall ${i.name}   # ${i.why.replace(/_/g, " ")}`),
        ],
      }
    : null;
  const tool = p.source.startsWith("poetry") ? "poetry" : p.source.startsWith("uv") ? "uv" : "pip";
  const python = pyItems.length
    ? {
        commands:
          tool === "uv"
            ? [`uv lock ${pyItems.map((i) => `--upgrade-package ${i.name}==${i.to}`).join(" ")}`, "uv sync"]
            : tool === "poetry"
              ? [...pyItems.map((i) => `poetry add "${i.name}==${i.to}"`), "poetry lock && poetry install"]
              : ["# pin these versions in requirements.txt, or install with the constraints file:", "pip install -c constraints.txt -r requirements.txt"],
        constraints: pyItems.map((i) => `${i.name}==${i.to}`).join("\n") + "\n",
      }
    : null;

  const bad = items.filter((i) => COMPROMISE.includes(i.why));
  const since = rows
    .filter((r) => bad.some((b) => `${b.name}@${b.from}` === `${r.name}@${r.version}`) && r.publishedAt)
    .map((r) => (typeof r.publishedAt === "number" ? r.publishedAt : Date.parse(r.publishedAt)))
    .filter((t) => !Number.isNaN(t))
    .sort((a, b) => a - b)[0];
  const incident = bad.length
    ? [
        `Treat every machine and CI runner that installed ${bad.slice(0, 3).map((b) => `${b.name}@${b.from}`).join(", ")}${bad.length > 3 ? ` and ${bad.length - 3} more` : ""} as compromised.`,
        `Rotate the tokens those machines could read: ${[...new Set(bad.map((b) => (b.ecosystem === "PyPI" ? "PyPI" : "npm")))].join(" and ")}, GitHub, cloud credentials and anything in .env files.`,
        since ? `Review CI logs and outbound network traffic since ${new Date(since).toISOString().slice(0, 10)}, when the first of these versions was published.` : "Review CI logs and outbound network traffic since these versions were installed.",
        "Delete node_modules / virtualenvs and caches before reinstalling, so the bad tarballs aren't reused.",
      ]
    : [];

  return { projectId: p.id, items, npm, python, incident, skipped: findings.filter((f) => (f.status === "open" || f.status === "confirmed") && !inScope(f)).length };
}
