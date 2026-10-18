import { writeFileSync } from "node:fs";
import { fetchTopPackages } from "../src/ingest/feeds.ts";

// pnpm refresh-top: re-download the 2,000 most downloaded npm and PyPI packages into server/data (takes a few minutes).
for (const [eco, file] of [["npm", "top-npm.json"], ["PyPI", "top-pypi.json"]] as const) {
  const m = await fetchTopPackages(eco);
  if (m.size < 1000) throw new Error(`only ${m.size} ${eco} packages came back; keeping the old list`);
  const packages = [...m].sort((a, b) => b[1] - a[1]);
  writeFileSync(`data/${file}`, JSON.stringify({ source: "packages.ecosyste.ms, top packages by downloads", fetched: new Date().toISOString().slice(0, 10), packages }) + "\n");
  console.log(eco, packages.length);
}
process.exit(0);
