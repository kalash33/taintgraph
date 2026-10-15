import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { paths } from "./config.ts";

// Every Cypher statement the product runs lives in /queries/<name>.cypher, so the README can link them
// and judges can read exactly what the agent's tools do.
const queries = new Map<string, string>();
for (const f of readdirSync(paths.queries)) if (f.endsWith(".cypher")) queries.set(f.slice(0, -7), readFileSync(join(paths.queries, f), "utf8").trim());

export function Q(name: string): string {
  const q = queries.get(name);
  if (!q) throw new Error(`Missing query file queries/${name}.cypher`);
  return q;
}

/** The query without its comment lines, for the "How I got here" view. */
export function shown(name: string): string {
  return Q(name)
    .split("\n")
    .filter((l) => !l.trimStart().startsWith("//"))
    .join("\n");
}
