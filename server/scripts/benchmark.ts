import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { ROOT } from "../src/config.ts";
import { close } from "../src/db.ts";
import { loadCases, runCase, table, type CaseResult } from "../src/benchmark.ts";

// pnpm bench: scan every case in benchmark/cases.json and write benchmark/RESULTS.md.
const org = "benchmark";
const results: CaseResult[] = [];
for (const c of loadCases()) {
  const r = await runCase(org, c);
  results.push(r);
  console.log(`${r.pass ? "pass" : "FAIL"}  ${c.id.padEnd(30)} ${r.verdict.padEnd(12)} ${r.signals.join(",")}  (${r.ms} ms)`);
}
const md = `# Benchmark: real incidents

Each row is one exact version from a real supply-chain incident (or a clean control), scanned as a one-package project with \`pnpm bench\`.
A row passes when Taintgraph calls an incident compromised and does not call a control compromised. Ordinary CVEs don't count either way.
A control can still read *suspicious*: that comes from ordinary high-severity CVEs (lodash, django), which Taintgraph reports as vulnerabilities, not compromise.
"possible_malware" means a malware advisory matches by version range or by its wording rather than naming the version explicitly; "removed" means the registry no longer serves the pinned version.

${table(results)}

Generated ${new Date().toISOString().slice(0, 10)}. Advisory data from OSV.dev changes over time; rerun to refresh.
`;
writeFileSync(join(ROOT, "benchmark", "RESULTS.md"), md);
console.log(`\n${md.split("\n").find((l) => l.startsWith("**"))}`);
await close();
