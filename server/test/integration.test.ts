import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { close, falkor, orgGraph, ping, read, run } from "../src/db.ts";
import { Q } from "../src/queries.ts";
import { getProject, simulateWorm, summary } from "../src/analysis.ts";
import { scan } from "../src/ingest/scout.ts";
import { loadSample } from "../src/samples.ts";
import { investigate } from "../src/agents/analyst.ts";
import { runSentinel } from "../src/agents/sentinel.ts";
import { drain } from "../src/agents/workers.ts";
import { recordVerdict } from "../src/memory.ts";
import type { Llm, Msg } from "../src/agents/llm.ts";
import type { InvestigateEvent } from "../src/types.ts";

// Against a real FalkorDB (docker compose up falkordb). Feeds are cached in Redis after the first run.
const ORG = `test-${Date.now().toString(36)}`;
const up = await ping();
const opts = { skip: up ? false : "FalkorDB is not running on FALKORDB_URL", timeout: 600_000 };

describe("graph, agents and memory", opts, () => {
  let chalk = "";
  let debug = "";
  let typo = "";
  before(async () => {
    chalk = await scan(ORG, loadSample("chalk-2025"));
    debug = await scan(ORG, loadSample("debug-2025"));
    typo = await scan(ORG, loadSample("typosquat"));
  });
  after(async () => {
    await (await falkor()).selectGraph(orgGraph(ORG)).delete().catch(() => {});
    await close();
  });

  test("routes only use the project's own edges", async () => {
    for (const id of [chalk, debug]) {
      const p = await getProject(ORG, id);
      const own = new Set((await read(ORG, Q("tree_edges"), { scanId: p.scanId, projectId: p.id })).map((e) => `${e.from}|${e.to}`));
      const direct = new Set((await read(ORG, Q("tree_direct"), { projectId: p.id })).map((d) => d.key));
      for (const f of (await summary(ORG, id)).findings) {
        assert.equal(f.path[0], `project/${id}`);
        assert.ok(direct.has(f.path[1]), `${f.path[1]} is a direct dependency of ${id}`);
        for (let i = 1; i < f.path.length - 1; i++) assert.ok(own.has(`${f.path[i]}|${f.path[i + 1]}`), `${f.path[i]} -> ${f.path[i + 1]} belongs to ${id}`);
      }
    }
  });

  test("a release is compared with the previous version on its own line, not the latest by date", async () => {
    const { compareVersions } = await import("../src/ingest/feeds.ts");
    const pairs = await read(ORG, "MATCH (p:Version)-[:PRECEDES]->(v:Version) RETURN p.version AS prev, v.version AS version, v.key AS key");
    assert.ok(pairs.length > 50, `${pairs.length} PRECEDES edges`);
    for (const r of pairs) assert.ok(compareVersions(r.prev, r.version) < 0, `${r.key}: previous ${r.prev}`);
    const incoming = await read(ORG, "MATCH (:Version)-[e:PRECEDES]->(v:Version) WITH v, count(e) AS n WHERE n > 1 RETURN v.key AS key");
    assert.deepEqual(incoming, [], "one previous release per version");
  });

  test("the fix plan pins malware to the clean previous release and never recommends a bad version", async () => {
    const { fixPlan } = await import("../src/fix.ts");
    const plan = await fixPlan(ORG, chalk);
    const item = plan.items.find((i) => i.name === "chalk" && i.from === "5.6.1")!;
    assert.equal(item.to, "5.6.0");
    assert.equal(item.action, "pin_previous");
    assert.equal(plan.npm!.overrides["chalk@5.6.1"], "5.6.0", "chalk has two versions, so the override is scoped to the bad one");
    assert.ok(plan.incident.length > 0);
    const bad = new Set((await read(ORG, "MATCH (:Advisory {kind: \"malware\"})-[:AFFECTS]->(v:Version) RETURN v.key AS key")).map((r) => r.key));
    for (const i of plan.items.filter((i) => i.to)) assert.ok(!bad.has(`npm/${i.name}@${i.to}`), `${i.name}@${i.to} is flagged`);
    const squat = (await fixPlan(ORG, typo)).items.find((i) => i.name === "lodahs")!;
    assert.equal(squat.action, "remove");
    assert.match(squat.note, /lodash/);
  });

  test("the September 2025 compromise is found with routes", async () => {
    const s = await summary(ORG, chalk);
    assert.equal(s.verdict, "compromised");
    const mal = s.findings.filter((f) => f.signal === "malware").map((f) => `${f.name}@${f.version}`);
    for (const v of ["chalk@5.6.1", "ansi-styles@6.2.2", "ansi-regex@6.2.1", "strip-ansi@7.1.1", "wrap-ansi@9.0.1", "slice-ansi@7.1.1"]) assert.ok(mal.includes(v), v);
  });

  test("a worm from one maintainer spreads past the first wave", async () => {
    const w = await simulateWorm(ORG, await getProject(ORG, chalk), "qix", 4);
    assert.ok(w.waves.length >= 2, `${w.waves.length} waves`);
    assert.ok(w.waves[1].poisoned.length > 0);
    assert.ok(w.poisonedShare > w.waves[0].poisoned.length / w.totalVersions);
  });

  test("a verdict in one project never hides malware in another", async () => {
    const f = (await summary(ORG, chalk)).findings.find((x) => x.name === "chalk" && x.signal === "malware")!;
    await recordVerdict(ORG, f.id, "dismissed", "test");
    await recordVerdict(ORG, f.id, "dismissed", "test again");
    const again = await scan(ORG, loadSample("debug-2025"));
    const g = (await summary(ORG, again)).findings.find((x) => x.name === "chalk" && x.signal === "malware")!;
    assert.equal(g.status, "open");
    assert.match(g.statusNote ?? "", /never skipped automatically/);
    const rules = await read(ORG, Q("memory_rules"));
    assert.equal(rules.filter((r) => r.rule.when === "malware").length, 0, "no rule is learned for malware");
  });

  test("the Sentinel finds a new advisory for an old scan and re-triages", async () => {
    await run(ORG, "MATCH (:Advisory {id: 'MAL-2025-25502'})-[e:AFFECTS]->() DELETE e");
    await run(ORG, "MATCH (f:Finding {project_id: $id, signal: 'malware'}) DETACH DELETE f", { id: typo });
    assert.equal((await summary(ORG, typo)).findings.filter((f) => f.signal === "malware").length, 0);
    const r = await runSentinel(ORG);
    assert.ok(r.hits.some((h) => h.projectId === typo && h.advisoryId === "MAL-2025-25502"), JSON.stringify(r.hits));
    const s = await summary(ORG, typo);
    assert.ok(s.findings.some((f) => f.signal === "malware" && f.name === "lodahs"));
    assert.equal(s.verdict, "compromised");
  });

  test("Scout -> Analyst -> Reporter hand off through Task nodes", async () => {
    await drain(ORG);
    const tasks = await read(ORG, Q("memory_tasks"));
    assert.ok(tasks.length >= 6);
    assert.ok(tasks.every((t) => t.task.status === "done"), JSON.stringify(tasks.map((t) => t.task.status)));
    const [rep] = await read(ORG, Q("report_get"), { projectId: chalk });
    assert.match(rep.markdown, /Compromised versions/);
  });

  test("a model that invents a package gets its answer rebuilt from the graph", async () => {
    const script: ((m: Msg[]) => any)[] = [
      () => ({ calls: [{ id: "1", name: "explain_package", args: { name: "lodahs" } }] }),
      () => ({ text: "lodahs@0.0.1-security is malware, and so is evil-pkg@6.6.6." }),
    ];
    let i = 0;
    const llm: Llm = {
      label: "mock via test",
      async chat(messages) {
        const r = { text: "", calls: [], truncated: false, ...script[Math.min(i++, script.length - 1)](messages) };
        return { ...r, message: { role: "assistant", content: r.text || null, ...(r.calls.length ? { tool_calls: r.calls.map((c: any) => ({ id: c.id, type: "function", function: { name: c.name, arguments: JSON.stringify(c.args) } })) } : {}) } };
      },
    };
    const events: InvestigateEvent[] = [];
    await investigate(ORG, typo, "is lodahs bad?", (e) => events.push(e), { llm });
    const answer = events.find((e) => e.type === "answer") as Extract<InvestigateEvent, { type: "answer" }>;
    assert.equal(answer.validated, false);
    assert.doesNotMatch(answer.text, /evil-pkg/);
    assert.match(answer.text, /lodahs@0\.0\.1-security/);
    assert.equal(answer.outcome, "answered");
  });

  test("unknown names are reported as unknown, with suggestions", async () => {
    const events: InvestigateEvent[] = [];
    await investigate(ORG, typo, "what about `lodas`?", (e) => events.push(e), { llm: null });
    const answer = events.find((e) => e.type === "answer") as Extract<InvestigateEvent, { type: "answer" }>;
    assert.equal(answer.outcome, "unknown_name");
    assert.match(answer.text, /lodash|lodahs/);
  });

  test("a repeated question is answered from memory, with the earlier evidence", async () => {
    const ask = async () => {
      const ev: InvestigateEvent[] = [];
      await investigate(ORG, chalk, "Is chalk compromised and how does it reach us?", (e) => ev.push(e), { llm: null });
      return ev;
    };
    await ask();
    const again = await ask();
    const answer = again.find((e) => e.type === "answer") as Extract<InvestigateEvent, { type: "answer" }>;
    assert.equal(answer.outcome, "from_memory");
    const reuse = again.find((e) => e.type === "step" && e.step.tool === "reuse_answer") as Extract<InvestigateEvent, { type: "step" }>;
    assert.ok(reuse.step.evidence.nodes.includes("npm/chalk@5.6.1"), JSON.stringify(reuse.step.evidence.nodes));
  });
});
