import { existsSync } from "node:fs";
import { join } from "node:path";
import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import fastifyStatic from "@fastify/static";
import { config, paths } from "./config.ts";
import { isValidOrg, ping } from "./db.ts";
import { accounts, dependencyGraph, getProject, listProjects, simulateWorm, summary, teams } from "./analysis.ts";
import { scan } from "./ingest/scout.ts";
import { githubFile } from "./ingest/github.ts";
import { loadSample, SAMPLES, scanSample } from "./samples.ts";
import { getInvestigation, investigate } from "./agents/analyst.ts";
import { llmFromEnv } from "./agents/llm.ts";
import { getReport } from "./agents/reporter.ts";
import { runSentinel } from "./agents/sentinel.ts";
import { startWorkers } from "./agents/workers.ts";
import { activateRule, memoryView, recordVerdict, type Verdict } from "./memory.ts";
import { seedWorkspace } from "./seed.ts";
import { fixPlan } from "./fix.ts";
import { scanChanges } from "./changes.ts";

const app = Fastify({ logger: { level: process.env.LOG_LEVEL ?? "info" }, bodyLimit: 26 * 1024 * 1024, trustProxy: config.trustProxy });
const bad = (msg: string, statusCode = 400) => Object.assign(new Error(msg), { statusCode });

// ───────────── workspace (org) and rate limits ─────────────
function org(req: FastifyRequest): string {
  const h = req.headers["x-taintgraph-org"];
  const o = (Array.isArray(h) ? h[0] : h)?.trim() || config.defaultOrg;
  if (!isValidOrg(o)) throw bad("x-taintgraph-org must be 1-64 letters, digits, - or _.");
  return o;
}

const LIMITS = { scan: [10, 60_000], ask: [20, 60_000], write: [60, 60_000], read: [600, 60_000] } as const;
const buckets = new Map<string, { n: number; reset: number }>();
function limit(kind: keyof typeof LIMITS) {
  return async (req: FastifyRequest, reply: FastifyReply) => {
    const [max, window] = LIMITS[kind];
    const key = `${kind}|${req.ip}`;
    const now = Date.now();
    const b = buckets.get(key);
    if (!b || b.reset < now) buckets.set(key, { n: 1, reset: now + window });
    else if (++b.n > max) {
      reply.header("retry-after", Math.ceil((b.reset - now) / 1000));
      throw bad("Too many requests. Wait a minute and try again.", 429);
    }
  };
}
setInterval(() => {
  const now = Date.now();
  for (const [k, b] of buckets) if (b.reset < now) buckets.delete(k);
}, 60_000).unref();

app.setErrorHandler((err: any, req, reply) => {
  const status = err.statusCode && err.statusCode < 500 ? err.statusCode : 500;
  if (status === 500) req.log.error(err);
  reply.status(status).send({ error: status === 500 ? "Something went wrong on the server. Check that FalkorDB is running." : err.message });
});

// ───────────── server-sent events ─────────────
function sse(reply: FastifyReply) {
  reply.hijack();
  reply.raw.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache, no-transform", connection: "keep-alive", "x-accel-buffering": "no" });
  const beat = setInterval(() => reply.raw.write(": keep-alive\n\n"), 15_000);
  return {
    send: (e: unknown) => !reply.raw.writableEnded && reply.raw.write(`data: ${JSON.stringify(e)}\n\n`),
    end: () => {
      clearInterval(beat);
      if (!reply.raw.writableEnded) reply.raw.end();
    },
  };
}

/** Errors the user can act on keep their message; infrastructure errors don't leak details. */
const userMessage = (e: any) => (e?.statusCode && e.statusCode < 500 ? e.message : "The scan failed on the server. Check that FalkorDB is running, then try again.");

// ───────────── routes ─────────────
app.get("/api/health", async () => {
  const llm = llmFromEnv();
  return { ok: true, falkordb: await ping(), llm: !!llm, agent: llm?.label ?? "built-in" };
});

app.get("/api/samples", async () => SAMPLES.map(({ id, title, description, filename }) => ({ id, title, description, filename })));

app.post("/api/scan", { preHandler: limit("scan") }, async (req, reply) => {
  const o = org(req);
  const body = (req.body ?? {}) as Record<string, unknown>;
  const s = typeof body.sample === "string" ? body.sample : null;
  const gh = typeof body.githubUrl === "string" ? body.githubUrl.trim() : null;
  const file = typeof body.filename === "string" && typeof body.content === "string" ? { filename: body.filename.slice(0, 200), content: body.content } : null;
  if (!s && !gh && !file) throw bad("Send { sample }, { filename, content } or { githubUrl }.");
  if (s && !SAMPLES.some((x) => x.id === s)) throw bad(`Unknown sample "${s}".`, 404);
  if (gh && !/^https:\/\/(www\.)?github\.com\/[\w.-]+\/[\w.-]+/.test(gh)) throw bad("Paste a GitHub repository URL like https://github.com/owner/repo");
  const out = sse(reply);
  try {
    let input: { filename: string; content: string; name?: string } = s ? loadSample(s) : file!;
    if (gh) {
      out.send({ type: "progress", stage: "Reading", message: "Looking for lockfiles and MCP configs in the repository", pct: 1 });
      const found = await githubFile(gh);
      out.send({ type: "progress", stage: "Reading", message: `Scanning ${found.path}${found.others.length ? ` (also found ${found.others.slice(0, 3).join(", ")}${found.others.length > 3 ? ", …" : ""}; link to a folder to scan another)` : ""}`, pct: 2 });
      input = found;
    }
    const projectId = s ? await scanSample(o, s, (e) => out.send(e)) : await scan(o, input, (e) => out.send(e));
    out.send({ type: "done", projectId });
  } catch (e: any) {
    if (!e?.statusCode) req.log.warn(e);
    out.send({ type: "error", message: userMessage(e) });
  } finally {
    out.end();
  }
});

app.get("/api/projects", { preHandler: limit("read") }, async (req) => listProjects(org(req)));
app.get<{ Params: { id: string } }>("/api/projects/:id", { preHandler: limit("read") }, async (req) => summary(org(req), req.params.id));
app.get<{ Params: { id: string } }>("/api/projects/:id/graph", { preHandler: limit("read") }, async (req) => {
  const o = org(req);
  return dependencyGraph(o, await getProject(o, req.params.id));
});
app.get<{ Params: { id: string } }>("/api/projects/:id/teams", { preHandler: limit("read") }, async (req) => {
  const o = org(req);
  return teams(o, await getProject(o, req.params.id));
});
app.get<{ Params: { id: string } }>("/api/projects/:id/accounts", { preHandler: limit("read") }, async (req) => {
  const o = org(req);
  return accounts(o, await getProject(o, req.params.id), 25);
});
app.post<{ Params: { id: string }; Body: { login?: unknown; waves?: unknown } }>("/api/projects/:id/simulate", { preHandler: limit("write") }, async (req) => {
  const o = org(req);
  const login = typeof req.body?.login === "string" ? req.body.login.trim().slice(0, 100) : "";
  if (!login) throw bad("Send { login }.");
  const waves = Math.min(6, Math.max(1, Number(req.body?.waves) || 4));
  return simulateWorm(o, await getProject(o, req.params.id), login, waves);
});
app.post<{ Params: { id: string }; Body: { question?: unknown; followUp?: unknown } }>("/api/projects/:id/ask", { preHandler: limit("ask") }, async (req, reply) => {
  const o = org(req);
  const question = typeof req.body?.question === "string" ? req.body.question.trim() : "";
  if (!question) throw bad("Send { question }.");
  if (question.length > 500) throw bad("Keep the question under 500 characters.");
  const followUp = typeof req.body?.followUp === "string" && /^inv-[a-z0-9]{8}$/.test(req.body.followUp) ? req.body.followUp : undefined;
  await getProject(o, req.params.id); // 404 before the stream opens
  const out = sse(reply);
  try {
    await investigate(o, req.params.id, question, (e) => out.send(e), { followUp });
  } catch (e: any) {
    req.log.warn(e);
    out.send({ type: "error", message: e?.statusCode ? e.message : "The investigation failed on the server." });
  } finally {
    out.end();
  }
});
app.get<{ Params: { id: string } }>("/api/projects/:id/changes", { preHandler: limit("read") }, async (req) => scanChanges(org(req), req.params.id));
app.get<{ Params: { id: string } }>("/api/projects/:id/fix", { preHandler: limit("read") }, async (req) => fixPlan(org(req), req.params.id));
app.get<{ Params: { id: string } }>("/api/projects/:id/report", { preHandler: limit("read") }, async (req) => {
  const o = org(req);
  await getProject(o, req.params.id);
  return { markdown: await getReport(o, req.params.id) };
});
app.get<{ Params: { id: string } }>("/api/investigations/:id", { preHandler: limit("read") }, async (req) => getInvestigation(org(req), req.params.id));

app.post<{ Params: { id: string }; Body: { verdict?: unknown; note?: unknown } }>("/api/findings/:id/verdict", { preHandler: limit("write") }, async (req) => {
  const v = req.body?.verdict;
  if (v !== "confirmed" && v !== "dismissed" && v !== "accepted") throw bad('verdict must be "confirmed", "dismissed" or "accepted".');
  return recordVerdict(org(req), req.params.id, v as Verdict, typeof req.body?.note === "string" ? req.body.note : "");
});
app.get("/api/memory", { preHandler: limit("read") }, async (req) => memoryView(org(req)));
app.post<{ Params: { id: string } }>("/api/rules/:id/activate", { preHandler: limit("write") }, async (req) => activateRule(org(req), req.params.id));
app.post("/api/sentinel", { preHandler: limit("scan") }, async (req) => runSentinel(org(req)));

// ───────────── the web app ─────────────
if (existsSync(join(paths.web, "index.html"))) {
  await app.register(fastifyStatic, { root: paths.web, wildcard: true });
  app.setNotFoundHandler((req, reply) => {
    if (req.method === "GET" && !req.url.startsWith("/api/")) return reply.sendFile("index.html");
    reply.status(404).send({ error: "Not found." });
  });
} else {
  app.setNotFoundHandler((req, reply) => reply.status(404).send({ error: req.url.startsWith("/api/") ? "Not found." : "The web app isn't built. Run pnpm build, or use the Vite dev server." }));
}

startWorkers();
// A fresh deployment opens with the samples already scanned (TAINTGRAPH_SEED=1), without delaying startup.
if (process.env.TAINTGRAPH_SEED === "1") void seedWorkspace(config.defaultOrg, (m) => app.log.info(m)).catch((e) => app.log.warn(e));
await app.listen({ port: config.port, host: process.env.HOST ?? "0.0.0.0" });
const llm = llmFromEnv();
app.log.info(`Taintgraph on http://localhost:${config.port} · FalkorDB ${(await ping()) ? "connected" : "NOT reachable at " + config.falkordbUrl} · Analyst: ${llm?.label ?? "built-in (set OPENROUTER_API_KEY or NVIDIA_API_KEY for a model)"}`);
