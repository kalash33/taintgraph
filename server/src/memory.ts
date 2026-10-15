import { read, run } from "./db.ts";
import { Q } from "./queries.ts";
import { getProject, loadFindings, verdictOf } from "./analysis.ts";
import { COMPROMISE, type FindingStatus, type MemoryView, type RuleView, type SignalId, type TaskView } from "./types.ts";

// Long-term memory lives in the graph next to the facts it is about:
//   episodic  : Investigation -[:HAS_STEP]-> Step, -[:CONCLUDED]-> Finding
//   semantic  : human verdicts on Finding nodes, recalled for the same version in any project
//   procedural: Rule nodes, proposed after repeated verdicts and active only once a human approves them
// Compromise signals (malware, possible malware, removed from the registry) are never learned or skipped automatically.

export type Verdict = Extract<FindingStatus, "confirmed" | "dismissed" | "accepted">;
const RULE_AFTER = 2; // matching verdicts before a rule is proposed
const notFound = (msg: string) => Object.assign(new Error(msg), { statusCode: 404 });

export async function recordVerdict(org: string, findingId: string, verdict: Verdict, note = ""): Promise<{ ok: true; proposedRule?: RuleView }> {
  const [row] = await run(org, Q("verdict_set"), { id: findingId, verdict, note: note.slice(0, 500) });
  if (!row) throw notFound(`No finding "${findingId}" in this workspace.`);
  if (row.projectId) {
    const p = await getProject(org, row.projectId);
    await run(org, Q("project_set_verdict"), { projectId: p.id, verdict: verdictOf(await loadFindings(org, p)) });
  }
  const signal = row.signal as SignalId;
  if (COMPROMISE.includes(signal)) return { ok: true };
  const [{ ids }] = await run(org, Q("verdict_count"), { verdict, signal });
  if ((ids as string[]).length < RULE_AFTER) return { ok: true };
  const then = verdict === "confirmed" ? "escalate" : "skip";
  const [r] = await run(org, Q("rule_propose"), { id: `rule-${signal}-${then}`, when: signal, then, confidence: Math.min(0.95, 0.5 + 0.15 * ids.length), from: ids });
  return { ok: true, proposedRule: r ? toRule(r.rule, ids) : undefined };
}

export async function activateRule(org: string, id: string) {
  const [rule] = await read(org, Q("rule_get"), { id });
  if (!rule) throw notFound(`No rule "${id}".`);
  if (COMPROMISE.includes(rule.when)) throw Object.assign(new Error("Rules can't act on malware or removed releases."), { statusCode: 400 });
  await run(org, Q("rule_activate"), { id });
  return { ok: true };
}

const toRule = (r: any, learnedFrom: string[]): RuleView => ({ id: r.id, when: r.when, then: r.then, status: r.status, confidence: r.confidence, learnedFrom });

export async function memoryView(org: string): Promise<MemoryView> {
  const [investigations, verdicts, rules, tasks] = await Promise.all([
    read(org, Q("memory_investigations")),
    read(org, Q("memory_verdicts")),
    read(org, Q("memory_rules")),
    read(org, Q("memory_tasks")),
  ]);
  return {
    investigations: investigations.map((i) => ({ id: i.id, question: i.question, projectId: i.projectId, projectName: i.projectName, startedAt: i.startedAt, agent: i.agent })),
    verdicts: verdicts.map((v) => ({ findingId: v.findingId, versionKey: v.versionKey, signal: v.signal, verdict: v.verdict, note: v.note, at: v.at })),
    rules: rules.map((r) => toRule(r.rule, r.learnedFrom ?? [])),
    tasks: tasks.map(
      ({ task: t, projectName }): TaskView => ({ id: t.id, type: t.type, forAgent: t.for_agent, status: t.status, claimedBy: t.claimed_by ?? undefined, createdAt: t.created_at, doneAt: t.done_at ?? undefined, projectName }),
    ),
  };
}
