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
    for (const i of plan.items.filter((i) => i.direct && i.to)) assert.ok(!Object.keys(plan.npm!.overrides).some((k) => k === i.name || k.startsWith(`${i.name}@`)), `direct dependency ${i.name} must not be overridden (npm EOVERRIDE)`);
    const bad = new Set((await read(ORG, "MATCH (:Advisory {kind: \"malware\"})-[:AFFECTS]->(v:Version) RETURN v.key AS key")).map((r) => r.key));
    for (const i of plan.items.filter((i) => i.to)) assert.ok(!bad.has(`npm/${i.name}@${i.to}`), `${i.name}@${i.to} is flagged`);
    const squat = (await fixPlan(ORG, typo)).items.find((i) => i.name === "lodahs")!;
    assert.equal(squat.action, "remove");
    assert.match(squat.note, /lodash/);
  });

  test("workspace exposure finds every project that installs a version, and every project an account reaches", async () => {
    const { toolByName, context } = await import("../src/agents/tools.ts");
    const ctx = context(ORG, await getProject(ORG, typo));
    const pkg = await toolByName.get("workspace_exposure")!.run(ctx, { name: "chalk@5.6.1" });
    assert.equal(pkg.outcome, "answered");
    const projects = new Set((pkg.data as any[]).map((r) => r.project));
    assert.ok(projects.has("aider-extension") && projects.has("vs-code-obsidian"), [...projects].join(","));
    const acct = await toolByName.get("workspace_exposure")!.run(ctx, { login: "qix" });
    assert.ok((acct.data as any[]).length >= 2);
    assert.equal((await toolByName.get("workspace_exposure")!.run(ctx, { name: "not-a-real-package-xyz" })).outcome, "unknown_name");
  });

  test("a rescan reports what changed, and which new versions are flagged", async () => {
    const { scanChanges } = await import("../src/changes.ts");
    const lock = (deps: Record<string, string>) => ({
      filename: "package-lock.json",
      name: "diff-demo",
      content: JSON.stringify({ name: "diff-demo", lockfileVersion: 3, packages: { "": { name: "diff-demo", dependencies: deps }, ...Object.fromEntries(Object.entries(deps).map(([n, v]) => [`node_modules/${n}`, { version: v }])) } }),
    });
    const id = await scan(ORG, lock({ chalk: "5.6.0", debug: "4.4.1" }));
    assert.equal((await scanChanges(ORG, id)).since, null);
    assert.equal(await scan(ORG, lock({ chalk: "5.6.1", debug: "4.4.1", is: "3.3.1" })), id, "same project after a lockfile update");
    const d = await scanChanges(ORG, id);
    assert.ok(d.since);
    assert.deepEqual(d.changed, [{ name: "chalk", from: ["5.6.0"], to: ["5.6.1"] }]);
    assert.deepEqual(d.added, [{ name: "is", version: "3.3.1" }]);
    const flagged = d.newlyFlagged.map((f) => `${f.name}@${f.version}`);
    assert.ok(flagged.includes("chalk@5.6.1") && flagged.includes("is@3.3.1"), flagged.join(","));
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

  test("a model that keeps calling tools is asked for its answer in the last round, not dropped", async () => {
    let finalSeen = false;
    const llm: Llm = {
      label: "eager via test",
      async chat(_m, _tools, opts) {
        if (opts?.final) {
          finalSeen = true;
          return { text: "chalk@5.6.1 is malware.", calls: [], truncated: false, message: { role: "assistant", content: "chalk@5.6.1 is malware." } };
        }
        const call = { id: `c${Math.random()}`, name: "explain_package", args: { name: "chalk" } };
        return { text: "", calls: [call], truncated: false, message: { role: "assistant", content: null, tool_calls: [{ id: call.id, type: "function", function: { name: call.name, arguments: "{}" } }] } };
      },
    };
    const events: InvestigateEvent[] = [];
    await investigate(ORG, chalk, "tell me everything about chalk, keep digging", (e) => events.push(e), { llm });
    const answer = events.find((e) => e.type === "answer") as Extract<InvestigateEvent, { type: "answer" }>;
    assert.ok(finalSeen);
    assert.equal(answer.text, "chalk@5.6.1 is malware.");
  });

  test("a learned skip rule never hides critical or high vulnerabilities", async () => {
    await run(ORG, "MERGE (r:Rule {id: 'rule-vulnerability-skip'}) SET r.when = 'vulnerability', r.then = 'skip', r.status = 'active', r.confidence = 0.9");
    try {
      const id = await scan(ORG, loadSample("chalk-2025"));
      const vulns = (await summary(ORG, id)).findings.filter((f) => f.signal === "vulnerability");
      assert.ok(vulns.some((f) => f.severity === "critical" || f.severity === "high"));
      for (const f of vulns) if (f.severity === "critical" || f.severity === "high") assert.notEqual(f.status, "skipped", `${f.name}@${f.version}`);
    } finally {
      await run(ORG, "MATCH (r:Rule {id: 'rule-vulnerability-skip'}) DETACH DELETE r");
    }
  });

  test("while a rescan is being written, readers keep the last complete scan", async () => {
    const before = await summary(ORG, chalk);
    await run(ORG, "MATCH (p:Project {id: $id}) SET p.latest_scan = 'scan-in-progress'", { id: chalk });
    try {
      const during = await summary(ORG, chalk);
      assert.equal(during.verdict, before.verdict);
      assert.equal(during.findings.length, before.findings.length);
    } finally {
      await run(ORG, "MATCH (p:Project {id: $id}) SET p.latest_scan = p.triaged_scan", { id: chalk });
    }
  });

  test("under concurrency every task is claimed by exactly one worker", async () => {
    const { createTask, claimTask, finishTask } = await import("../src/agents/tasks.ts");
    await drain(ORG); // start from an empty queue
    const ids = await Promise.all(Array.from({ length: 40 }, () => createTask(ORG, chalk, "report", "reporter", { test: true })));
    const claimed: string[] = [];
    await Promise.all(
      Array.from({ length: 8 }, async (_, w) => {
        for (let t = await claimTask(ORG, "reporter", `race-${w}`); t; t = await claimTask(ORG, "reporter", `race-${w}`)) {
          claimed.push(t.id);
          await finishTask(ORG, t.id, "done", "race test");
        }
      }),
    );
    assert.equal(new Set(claimed).size, claimed.length, "no task claimed twice");
    assert.deepEqual([...claimed].sort(), [...ids].sort(), "every task claimed");
  });

  test("a follow-up question continues the conversation", async () => {
    const first = await investigate(ORG, chalk, "Is chalk compromised?", () => {}, { llm: null });
    const steps: string[] = [];
    let answer = "";
    const second = await investigate(ORG, chalk, "Who publishes it?", (e) => { if (e.type === "step") steps.push(e.step.tool); if (e.type === "answer") answer = e.text; }, { llm: null, followUp: first });
    const { getInvestigation } = await import("../src/agents/analyst.ts");
    assert.equal((await getInvestigation(ORG, second)).followsId, first);
    assert.ok(steps.includes("explain_package"), steps.join(","));
    assert.match(answer, /chalk/);
  });

  test("community detection finds the chalk maintainer team, and connected components bound the worm", async () => {
    const { teams } = await import("../src/analysis.ts");
    const r = await teams(ORG, await getProject(ORG, chalk));
    const team = r.teams.find((x) => x.accounts.includes("qix"));
    assert.ok(team, r.teams.map((x) => x.accounts.slice(0, 3).join("/")).join("; "));
    assert.ok(team.flagged, "the team that can publish chalk@5.6.1 is flagged");
    assert.ok(r.network.accounts > 10 && r.network.accounts <= r.network.totalAccounts);
  });

  test("the lockfile-update sample is scanned before and after, so the changes show", async () => {
    const { scanSample } = await import("../src/samples.ts");
    const { scanChanges } = await import("../src/changes.ts");
    const id = await scanSample(ORG, "lockfile-update");
    const d = await scanChanges(ORG, id);
    assert.deepEqual(d.changed, [{ name: "chalk", from: ["5.6.0"], to: ["5.6.1"] }]);
    assert.deepEqual(d.newlyFlagged.map((f) => `${f.name}@${f.version}`).sort(), ["chalk@5.6.1", "is@3.3.1"]);
  });

  test("the dashboard insights come from the graph", async () => {
    const { insights } = await import("../src/insights.ts");
    const d = await insights(ORG, chalk);
    assert.ok(d.compromised >= 5, String(d.compromised)); // an earlier test dismissed chalk in this project
    assert.ok(d.deepest && d.deepest.hops >= 2);
    assert.ok(d.topAccount && d.topAccount.share > 0);
    assert.ok(d.worm && d.worm.poisonedShare > 0);
    assert.ok(d.topTeam && d.network.accounts > 0);
    assert.ok(d.fixes > 0 && d.incident);
  });
});
