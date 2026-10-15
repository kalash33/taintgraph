import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ROOT } from "./config.ts";
import { summary } from "./analysis.ts";
import { scan } from "./ingest/scout.ts";
import { COMPROMISE, type Ecosystem, type ProjectSummary } from "./types.ts";

// Real incidents and clean controls (benchmark/cases.json), each scanned as a one-package project.

export interface Case {
  id: string;
  ecosystem: Ecosystem;
  name: string;
  version: string;
  date: string;
  expect: "compromised" | "clean";
  what: string;
}
export interface CaseResult {
  case: Case;
  verdict: ProjectSummary["verdict"];
  signals: string[];
  advisories: string[];
  pass: boolean;
  ms: number;
}

export const loadCases = (): Case[] => JSON.parse(readFileSync(join(ROOT, "benchmark", "cases.json"), "utf8")).cases;

/** The smallest input that names exactly one installed version. */
export function lockfileFor(c: Case): { filename: string; content: string; name: string } {
  if (c.ecosystem === "PyPI") return { filename: "requirements.txt", content: `${c.name}==${c.version}\n`, name: `bench-${c.id}` };
  const lock = {
    name: `bench-${c.id}`,
    lockfileVersion: 3,
    packages: { "": { name: `bench-${c.id}`, dependencies: { [c.name]: c.version } }, [`node_modules/${c.name}`]: { version: c.version } },
  };
  return { filename: "package-lock.json", content: JSON.stringify(lock), name: `bench-${c.id}` };
}

export async function runCase(org: string, c: Case): Promise<CaseResult> {
  const t0 = Date.now();
  const s = await summary(org, await scan(org, lockfileFor(c)));
  const live = s.findings.filter((f) => f.status === "open" || f.status === "confirmed");
  const compromised = live.some((f) => COMPROMISE.includes(f.signal));
  return {
    case: c,
    verdict: s.verdict,
    signals: [...new Set(live.map((f) => f.signal))],
    advisories: [...new Set(live.flatMap((f) => f.advisories.map((a) => a.id)))],
    pass: c.expect === "compromised" ? compromised : !compromised,
    ms: Date.now() - t0,
  };
}

export function table(results: CaseResult[]): string {
  const hit = results.filter((r) => r.case.expect === "compromised");
  const clean = results.filter((r) => r.case.expect === "clean");
  const rows = results.map(
    (r) =>
      `| ${r.case.date} | ${r.case.ecosystem} | \`${r.case.name}@${r.case.version}\` | ${r.case.expect} | ${r.verdict} | ${r.signals.filter((s) => s !== "vulnerability").join(", ") || "–"} | ${[...r.advisories].sort((a, b) => Number(b.startsWith("MAL-")) - Number(a.startsWith("MAL-"))).slice(0, 2).join(", ") || "–"} | ${r.pass ? "✅" : "❌"} |`,
  );
  return [
    `**Detected ${hit.filter((r) => r.pass).length} of ${hit.length} real incidents; ${clean.filter((r) => !r.pass).length} false alarms on ${clean.length} clean controls.**`,
    "",
    "| Date | Registry | Version | Expected | Verdict | Signals | Advisory | |",
    "|---|---|---|---|---|---|---|---|",
    ...rows,
  ].join("\n");
}
