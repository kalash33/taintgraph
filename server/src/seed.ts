import { listProjects } from "./analysis.ts";
import { scan } from "./ingest/scout.ts";
import { loadSample, SAMPLES } from "./samples.ts";

/** Scan every sample into an empty workspace, so a fresh deployment opens with real projects. */
export async function seedWorkspace(org: string, log: (msg: string) => void = () => {}): Promise<number> {
  if ((await listProjects(org)).length) return 0;
  let n = 0;
  for (const s of SAMPLES) {
    try {
      await scan(org, loadSample(s.id));
      n++;
      log(`seeded ${s.id}`);
    } catch (e: any) {
      log(`could not seed ${s.id}: ${e.message}`);
    }
  }
  return n;
}
