import { readFileSync, writeFileSync } from "node:fs";
import { basename } from "node:path";
import { config } from "./config.ts";
import { short, summary } from "./analysis.ts";
import { scan } from "./ingest/scout.ts";
import { githubFile } from "./ingest/github.ts";
import { loadSample, SAMPLES } from "./samples.ts";
import { COMPROMISE, type FindingView, type ProjectSummary, type Severity } from "./types.ts";

const HELP = `Usage: pnpm scan <lockfile | MCP config | GitHub URL | sample> [options]

  --org <name>        Workspace (default "demo")
  --ask "<question>"  Ask the Analyst after the scan
  --fail-on <level>   Exit 1 if an open finding is at or above: malware | critical | high | medium
  --json              Print the project summary as JSON
  --sarif <file>      Write findings as SARIF 2.1.0 (GitHub code scanning)
  --fix               Print the fix plan: safe versions, overrides, incident steps

Exit codes: 0 ok, 1 findings at or above --fail-on, 2 the scan could not run.
Samples: ${SAMPLES.map((s) => s.id).join(", ")}`;

const args = process.argv.slice(2);
const opt = (n: string) => {
  const i = args.indexOf(`--${n}`);
  return i < 0 ? undefined : args.splice(i, 2)[1];
};
const flag = (n: string) => {
  const i = args.indexOf(`--${n}`);
  return i < 0 ? false : (args.splice(i, 1), true);
};
const org = opt("org") ?? config.defaultOrg;
const question = opt("ask");
const failOn = opt("fail-on");
const sarif = opt("sarif");
const wantFix = flag("fix");
const json = flag("json");
if (flag("help") || !args[0]) {
  console.log(HELP);
  process.exit(args[0] ? 0 : 2);
}
if (failOn && !["malware", "critical", "high", "medium"].includes(failOn)) {
  console.error(`--fail-on must be malware, critical, high or medium`);
  process.exit(2);
}
const say = json ? () => {} : console.log;
const target = args[0];

let s: ProjectSummary;
let file = target;
try {
  const input = SAMPLES.some((x) => x.id === target)
    ? loadSample(target)
    : /^https?:\/\/(www\.)?github\.com\//.test(target)
      ? await githubFile(target).then((f) => (say(`Scanning ${f.path}${f.others.length ? ` (also found: ${f.others.slice(0, 5).join(", ")})` : ""}`), f))
      : { filename: basename(target), content: readFileSync(target, "utf8") };
  file = SAMPLES.some((x) => x.id === target) ? `fixtures/${input.filename}` : target;
  const t0 = Date.now();
  const id = await scan(org, input, (e) => e.type === "progress" && say(`[${String(e.pct).padStart(3)}%] ${e.stage}: ${e.message}`));
  s = await summary(org, id);
  say(`\n${s.name}: ${s.verdict.toUpperCase()} in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
  say(`${s.counts.packages} versions, ${s.counts.edges} edges, ${s.counts.accounts} accounts, ${s.counts.advisories} advisories`);
  for (const f of s.findings) say(`- [${f.severity}] ${f.status === "skipped" ? "(skipped) " : ""}${f.title}  ${f.path.map((k) => (k.startsWith("project/") ? s.name : short(k))).join(" → ")}`);
  say("Top accounts:", s.topAccounts.slice(0, 5).map((a) => `${a.login} ${(a.share * 100).toFixed(0)}%`).join(", "));
} catch (e: any) {
  console.error(`Scan failed: ${e.message}`);
  process.exit(2);
}

if (json) console.log(JSON.stringify(s, null, 2));
if (sarif) {
  writeFileSync(sarif, JSON.stringify(toSarif(s, file), null, 2));
  say(`SARIF written to ${sarif}`);
}
if (wantFix) {
  const { fixPlan } = await import("./fix.ts");
  const plan = await fixPlan(org, s.id);
  say(`\nFix plan (${plan.items.length} change${plan.items.length === 1 ? "" : "s"}${plan.skipped ? `, ${plan.skipped} lower-severity findings left out` : ""}):`);
  for (const i of plan.items) say(`  ${i.to ? `${i.name}@${i.from} → ${i.to}` : i.action === "no_fix" ? `${i.name}@${i.from}: no fix released yet` : `remove ${i.name}@${i.from}`}${i.majorChange ? "  [major version]" : ""}  (${i.direct ? "direct" : "override"}, ${i.why.replace(/_/g, " ")}) ${i.note}`);
  if (plan.npm) say(`\npackage.json:\n${JSON.stringify({ overrides: plan.npm.overrides }, null, 2)}`);
  if (plan.python) say(`\n${plan.python.commands.join("\n")}`);
  if (plan.incident.length) say(`\nIncident response:\n${plan.incident.map((x) => `  - ${x}`).join("\n")}`);
  if (json) console.log(JSON.stringify(plan, null, 2));
}
if (question) {
  const { investigate } = await import("./agents/analyst.ts");
  say(`\nQ: ${question}`);
  await investigate(org, s.id, question, (e) => {
    if (e.type === "step") say(`  ${e.step.index}. ${e.step.label} (${e.step.tool}) -> ${e.step.outcome}`);
    if (e.type === "answer") say(`\n${e.text}\n[${e.outcome}${e.validated ? "" : ", rebuilt from graph results"}]`);
    if (e.type === "error") console.error("error:", e.message);
  });
}

const RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const open = s.findings.filter((f) => f.status === "open" || f.status === "confirmed");
const failing = !failOn ? [] : failOn === "malware" ? open.filter((f) => COMPROMISE.includes(f.signal)) : open.filter((f) => RANK[f.severity] <= RANK[failOn as Severity]);
if (failing.length) {
  console.error(`Taintgraph: ${failing.length} open finding${failing.length === 1 ? "" : "s"} at or above "${failOn}".`);
  process.exit(1);
}
process.exit(0);

function toSarif(s: ProjectSummary, uri: string) {
  const level = (f: FindingView) => (RANK[f.severity] <= 1 ? "error" : f.severity === "medium" ? "warning" : "note");
  const route = (f: FindingView) => f.path.map((k) => (k.startsWith("project/") ? s.name : short(k))).join(" -> ");
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "Taintgraph", informationUri: "https://github.com/kalash33/taintgraph", rules: [...new Set(s.findings.map((f) => f.signal))].map((id) => ({ id, name: id, shortDescription: { text: id.replace(/_/g, " ") } })) } },
        results: s.findings
          .filter((f) => f.status !== "skipped")
          .map((f) => ({
            ruleId: f.signal,
            level: level(f),
            message: { text: `${f.title}. Route: ${route(f)}.${f.fix ? ` Fix: ${f.fix}` : ""}` },
            locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: 1 } } }],
            partialFingerprints: { taintgraphFinding: f.id },
            properties: { package: `${f.name}@${f.version}`, advisories: f.advisories.map((a) => a.id) },
          })),
      },
    ],
  };
}
