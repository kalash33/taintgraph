# Contributing

## Setup

```bash
docker compose up -d falkordb      # FalkorDB on 127.0.0.1:6380
pnpm install
pnpm -C web dev                    # UI with hot reload on :5173, proxied to the API
pnpm -C server dev                 # API on :8787, restarts on change
```

## Checks

```bash
pnpm -C server typecheck
pnpm test        # unit, integration (real FalkorDB) and real-world incident tests
pnpm bench       # rewrites benchmark/RESULTS.md
pnpm build       # typechecks and builds the web app
```

Integration tests create a throwaway workspace and delete it afterwards. The first run downloads feed data; later runs use the cache in FalkorDB.

## Conventions

- **Cypher lives in `queries/`**, one query per file, loaded with `Q("name")`. Don't build Cypher from strings.
- **Agent tools are read-only** (`read()` → `GRAPH.RO_QUERY`) and return a typed outcome.
- **Text from package authors goes through `untrusted()`** before it is stored in a finding or shown.
- **The API contract is `server/src/types.ts`**; the web app imports it directly.
- **New detection logic needs a case** in `benchmark/cases.json`: a real incident it catches or a clean version it must not flag.

## Adding a real-world case

Add an entry to `benchmark/cases.json` with the exact version, the date and one line on what happened, then run `pnpm bench`. The incident test suite picks it up automatically.
