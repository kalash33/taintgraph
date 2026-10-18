import { listProjects } from "./analysis.ts";
import { insights } from "./insights.ts";
import { SAMPLES, scanSample } from "./samples.ts";

/** Scan every sample into an empty workspace, so a fresh deployment opens with real projects. */
export async function seedWorkspace(org: string, log: (msg: string) => void = () => {}): Promise<number> {
  if ((await listProjects(org)).length) return 0;
  let n = 0;
  for (const s of SAMPLES) {
    try {
      await scanSample(org, s.id);
      n++;
      log(`seeded ${s.id}`);
    } catch (e: any) {
      log(`could not seed ${s.id}: ${e.message}`);
    }
  }
  // Warm the dashboard numbers, so the first visitor doesn't wait for them.
  for (const p of await listProjects(org)) await insights(org, p.id).catch(() => {});
  return n;
}
