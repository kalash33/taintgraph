import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { config } from "./config.ts";
import { close, isValidOrg, read } from "./db.ts";
import { Q } from "./queries.ts";
import { getProject, listProjects, summary } from "./analysis.ts";
import { scan } from "./ingest/scout.ts";
import { loadSample, SAMPLES } from "./samples.ts";
import { investigate } from "./agents/analyst.ts";
import { context, toolByName } from "./agents/tools.ts";
import { recordVerdict } from "./memory.ts";
import { COMPROMISE } from "./types.ts";

// Taintgraph as an MCP server: a coding agent can scan the lockfile it is about to change, ask how a package reaches
// the app, and record what it decided. Everything except scan and record_verdict is read-only.
// stdout belongs to the protocol, so logs go to stderr.

console.log = console.error;
const org = process.env.TAINTGRAPH_ORG || config.defaultOrg;
if (!isValidOrg(org)) throw new Error("TAINTGRAPH_ORG must be 1-64 letters, digits, - or _.");

const server = new McpServer({ name: "taintgraph", version: "1.0.0" });
const text = (t: string) => ({ content: [{ type: "text" as const, text: t }] });
const fail = (t: string) => ({ content: [{ type: "text" as const, text: t }], isError: true });
const guard =
  <A>(fn: (a: A) => Promise<ReturnType<typeof text>>) =>
  async (a: A) => {
    try {
      return await fn(a);
    } catch (e: any) {
      return fail(e?.statusCode ? e.message : `Taintgraph failed: ${String(e?.message ?? e).slice(0, 200)}`);
    }
  };

server.registerTool(
  "scan",
  {
    description: `Scan a lockfile (package-lock.json, pnpm-lock.yaml, yarn.lock, bun.lock, uv.lock, poetry.lock, requirements.txt) or an MCP config into the supply-chain graph. Pass a local path, or a sample id (${SAMPLES.map((s) => s.id).join(", ")}). Returns the verdict and findings.`,
    inputSchema: { path: z.string().optional(), sample: z.string().optional() },
  },
  guard(async ({ path, sample }: { path?: string; sample?: string }) => {
    if (!path && !sample) return fail("Pass path or sample.");
    const input = sample ? loadSample(sample) : { filename: basename(path!), content: readFileSync(path!, "utf8") };
    const id = await scan(org, input);
    const s = await summary(org, id);
    const lines = s.findings.filter((f) => f.status !== "skipped").slice(0, 15).map((f) => `- [${f.severity}] ${f.title} (finding ${f.id})`);
    return text(`Project ${s.name} (id ${s.id}): ${s.verdict.toUpperCase()}. ${s.counts.packages} versions, ${s.findings.length} findings.\n${lines.join("\n")}`);
  }),
);

server.registerTool(
  "list_projects",
  { description: "Projects already scanned in this workspace, with their verdicts.", inputSchema: {} },
  guard(async () => {
    const list = await listProjects(org);
    return text(list.length ? list.map((p) => `${p.id}  ${p.name}  ${p.verdict}  (${p.source})`).join("\n") : "No projects yet. Use scan first.");
  }),
);

server.registerTool(
  "ask",
  {
    description: "Ask Taintgraph's Analyst a question about a scanned project, e.g. 'Is chalk compromised and how does it reach us?' or 'What if maintainer qix is phished?'. It answers from the graph and shows its steps.",
    inputSchema: { projectId: z.string(), question: z.string().max(500) },
  },
  guard(async ({ projectId, question }: { projectId: string; question: string }) => {
    const steps: string[] = [];
    let answer = "";
    let error = "";
    await investigate(org, projectId, question, (e) => {
      if (e.type === "step") steps.push(`${e.step.index}. ${e.step.label}: ${e.step.outcome}`);
      if (e.type === "answer") answer = `${e.text}\n\n[${e.outcome}${e.validated ? "" : ", rebuilt from graph results"}]`;
      if (e.type === "error") error = e.message;
    });
    return error ? fail(error) : text(`${answer}\n\nSteps:\n${steps.join("\n")}`);
  }),
);

// The Analyst's own graph tools, exposed one-to-one.
for (const name of ["explain_package", "trace_exposures", "fix_plan", "workspace_exposure", "scan_changes", "top_accounts", "maintainer_teams", "simulate_worm", "mcp_servers", "chokepoints"]) {
  const t = toolByName.get(name)!;
  const props = (t.spec.parameters as any).properties ?? {};
  const shape: Record<string, z.ZodTypeAny> = { projectId: z.string() };
  for (const [k, v] of Object.entries<any>(props)) shape[k] = (v.type === "integer" ? z.number().int() : z.string()).optional();
  server.registerTool(
    name,
    { description: t.spec.description, inputSchema: shape },
    guard(async ({ projectId, ...args }: Record<string, any>) => {
      const r = await t.run(context(org, await getProject(org, String(projectId))), args);
      return text(`${r.summary}\n\n[${r.outcome}]\n${JSON.stringify(r.data, null, 1).slice(0, 6000)}`);
    }),
  );
}

server.registerTool(
  "record_verdict",
  {
    description: "Record a decision about a finding: confirmed (real threat), dismissed (not a threat) or accepted (risk accepted). Taintgraph learns from repeated verdicts. An agent can't dismiss or accept malware or removed-release findings: a person has to do that in the web app.",
    inputSchema: { findingId: z.string(), verdict: z.enum(["confirmed", "dismissed", "accepted"]), note: z.string().max(500).optional() },
  },
  guard(async ({ findingId, verdict, note }: { findingId: string; verdict: "confirmed" | "dismissed" | "accepted"; note?: string }) => {
    const [row] = await read(org, Q("finding_signal"), { id: findingId });
    if (!row) return fail(`No finding "${findingId}".`);
    if (verdict !== "confirmed" && COMPROMISE.includes(row.signal)) return fail(`Finding ${findingId} is ${row.signal.replace(/_/g, " ")}. Only a person can clear that, in the Taintgraph web app.`);
    const r = await recordVerdict(org, findingId, verdict, `${note ?? ""} (recorded by an agent over MCP)`.trim());
    return text(`Recorded ${verdict} for ${findingId}.${r.proposedRule ? ` Proposed rule: ${r.proposedRule.when} → ${r.proposedRule.then} (needs a person to activate it).` : ""}`);
  }),
);

const transport = new StdioServerTransport();
// Exit when the client goes away; the open database connections would otherwise keep the process alive.
const shutdown = () => void close().finally(() => process.exit(0));
transport.onclose = shutdown;
process.stdin.on("end", shutdown);
await server.connect(transport);
console.error(`[taintgraph mcp] workspace "${org}" ready`);
