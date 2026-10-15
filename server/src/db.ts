import { FalkorDB } from "falkordb";
import { createClient } from "redis";
import { config } from "./config.ts";

type Params = Record<string, unknown>;
type Redis = ReturnType<typeof createClient>;

let falkorP: Promise<FalkorDB> | undefined;
let redisP: Promise<Redis> | undefined;

/** Connections are memoized, but a failed attempt is not: FalkorDB may still be starting. */
export function falkor(): Promise<FalkorDB> {
  falkorP ??= FalkorDB.connect({ url: config.falkordbUrl }).catch((e) => {
    falkorP = undefined;
    throw e;
  });
  return falkorP;
}

/** Plain Redis on the same FalkorDB instance: used for the HTTP cache (no second datastore). */
export function redis(): Promise<Redis> {
  redisP ??= (async () => {
    const c = createClient({ url: config.falkordbUrl });
    c.on("error", (e) => console.error("[redis]", e.message));
    await c.connect();
    return c as Redis;
  })().catch((e) => {
    redisP = undefined;
    throw e;
  });
  return redisP;
}

/** One graph per workspace (tenant): isolation comes from the graph boundary, not a WHERE clause. */
export const PREFIX = "up:org:";
export const orgGraph = (org: string) => `${PREFIX}${org}`;
export const isValidOrg = (org: string) => /^[A-Za-z0-9_-]{1,64}$/.test(org);

export async function run<T = Record<string, any>>(org: string, cypher: string, params: Params = {}): Promise<T[]> {
  const g = (await falkor()).selectGraph(orgGraph(org));
  const res = await g.query<T>(cypher, { params: params as any, TIMEOUT: 60_000 });
  return (res.data ?? []) as T[];
}

/** Read-only (GRAPH.RO_QUERY). Every agent tool goes through this, so the agent can never write. */
export async function read<T = Record<string, any>>(org: string, cypher: string, params: Params = {}): Promise<T[]> {
  const g = (await falkor()).selectGraph(orgGraph(org));
  try {
    const res = await g.roQuery<T>(cypher, { params: params as any, TIMEOUT: 30_000 });
    return (res.data ?? []) as T[];
  } catch (e: any) {
    if (/empty key|does not exist/i.test(e.message)) return []; // a workspace that has never been scanned
    throw e;
  }
}

/** UNWIND-batched writes, 500 rows per query. */
export async function batched(org: string, cypher: string, rows: unknown[], params: Params = {}) {
  for (let i = 0; i < rows.length; i += 500) await run(org, cypher, { ...params, rows: rows.slice(i, i + 500) });
}

export async function listOrgs(): Promise<string[]> {
  return (await (await falkor()).list()).filter((g) => g.startsWith(PREFIX)).map((g) => g.slice(PREFIX.length));
}

export async function ping(): Promise<boolean> {
  try {
    return (await (await redis()).ping()) === "PONG";
  } catch {
    return false;
  }
}

/** Close both connections (tests and CLI exits). */
export async function close() {
  const [f, r] = [falkorP, redisP];
  falkorP = redisP = undefined;
  await Promise.allSettled([f?.then((c) => c.close()), r?.then((c) => c.quit())]);
}
