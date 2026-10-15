import { randomUUID } from "node:crypto";
import { run } from "../db.ts";
import { Q } from "../queries.ts";

// Shared state between agents lives in the graph as Task nodes: Scout -> Analyst -> Reporter.

export async function createTask(org: string, projectId: string, type: "analyze" | "report", forAgent: "analyst" | "reporter", payload: Record<string, unknown> = {}) {
  const id = `task-${randomUUID().slice(0, 8)}`;
  await run(org, Q("task_create"), { projectId, id, type, forAgent, payload: JSON.stringify(payload) });
  return id;
}

export async function claimTask(org: string, agent: "analyst" | "reporter", worker: string) {
  const [row] = await run(org, Q("task_claim"), { agent, worker });
  return row?.task ? { id: row.task.id as string, type: row.task.type as string, projectId: row.projectId as string, payload: JSON.parse(row.task.payload ?? "{}") } : null;
}

export async function finishTask(org: string, id: string, status: "done" | "error", result: string) {
  await run(org, Q("task_done"), { id, status, result: result.slice(0, 300) });
}
