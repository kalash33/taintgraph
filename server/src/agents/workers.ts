import { listOrgs, run } from "../db.ts";
import { Q } from "../queries.ts";
import { investigate } from "./analyst.ts";
import { llmFromEnv } from "./llm.ts";
import { buildReport } from "./reporter.ts";
import { claimTask, createTask, finishTask } from "./tasks.ts";

// Agents coordinate only through Task nodes in each workspace graph: the Scout leaves an "analyze" task, the Analyst
// claims it, investigates and leaves a "report" task, and the Reporter writes the report. Claims are atomic, and
// tasks held by a worker that died go back to the queue.

export const AUTO_QUESTION = "What in this project is compromised or suspicious, and how does it reach the app?";
// Workers are named without the hostname, which would otherwise show up in the UI.
const worker = process.env.TAINTGRAPH_WORKER || `worker-${process.pid}`;
let timer: NodeJS.Timeout | null = null;
let busy = false;

export async function tick(): Promise<number> {
  if (busy) return 0;
  busy = true;
  let done = 0;
  try {
    for (const org of await listOrgs()) {
      try {
        await run(org, Q("task_reclaim"));
        done += await drain(org);
      } catch (e: any) {
        console.warn(`[workers] ${org}:`, e.message);
      }
    }
  } finally {
    busy = false;
  }
  return done;
}

/** Work through one workspace's queue. */
export async function drain(org: string): Promise<number> {
  let done = 0;
  // The automatic handoff uses the built-in investigator unless TAINTGRAPH_AUTO_LLM=1, so scans don't spend model credits.
  const llm = process.env.TAINTGRAPH_AUTO_LLM === "1" ? llmFromEnv() : null;
  for (let task = await claimTask(org, "analyst", worker); task; task = await claimTask(org, "analyst", worker)) {
    try {
      const id = await investigate(org, task.projectId, AUTO_QUESTION, () => {}, { llm });
      await createTask(org, task.projectId, "report", "reporter", { investigationId: id });
      await finishTask(org, task.id, "done", `investigation ${id}`);
    } catch (e: any) {
      await finishTask(org, task.id, "error", e.message);
    }
    done++;
  }
  for (let task = await claimTask(org, "reporter", worker); task; task = await claimTask(org, "reporter", worker)) {
    try {
      const markdown = await buildReport(org, task.projectId);
      await finishTask(org, task.id, "done", `report, ${markdown.length} chars`);
    } catch (e: any) {
      await finishTask(org, task.id, "error", e.message);
    }
    done++;
  }
  return done;
}

export function startWorkers(everyMs = 2000) {
  if (timer) return;
  timer = setInterval(() => void tick(), everyMs);
  timer.unref();
}

export function stopWorkers() {
  if (timer) clearInterval(timer);
  timer = null;
}
