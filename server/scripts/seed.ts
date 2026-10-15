import { config } from "../src/config.ts";
import { close } from "../src/db.ts";
import { seedWorkspace } from "../src/seed.ts";

// pnpm seed [workspace]: scan every sample into the workspace if it has no projects yet.
const org = process.argv[2] ?? config.defaultOrg;
const n = await seedWorkspace(org, console.log);
console.log(n ? `Seeded ${n} projects into "${org}".` : `"${org}" already has projects; nothing to do.`);
await close();
