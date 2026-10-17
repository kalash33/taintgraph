# Using Taintgraph

Four ways in: the web app, the CLI (and CI), the MCP server, and the HTTP API. All of them share the same workspaces.

## Web app

`pnpm start` (or `docker compose up`) serves it at http://localhost:8787. Drop a lockfile, paste one, give a public GitHub URL, or click a sample. The workspace is chosen in the browser and sent as the `x-taintgraph-org` header.

## CLI

```bash
pnpm scan path/to/package-lock.json
pnpm scan https://github.com/owner/repo                     # finds lockfiles in subfolders too
pnpm scan https://github.com/owner/repo/tree/main/apps/web  # a folder in a monorepo
pnpm scan package-lock.json --fix                           # the fix plan
pnpm scan chalk-2025 --ask "What if qix is phished?"
pnpm scan uv.lock --org payments --fail-on malware --sarif taintgraph.sarif
pnpm scan pnpm-lock.yaml --json > summary.json
```

| Option | |
|---|---|
| `--org <name>` | workspace (default `demo`) |
| `--ask "<question>"` | ask the Analyst after the scan |
| `--fail-on <level>` | exit 1 if an open finding is at or above `malware`, `critical`, `high` or `medium` |
| `--json` | print the project summary as JSON |
| `--sarif <file>` | write SARIF 2.1.0 for GitHub code scanning |
| `--fix` | print the fix plan: safe versions, the `overrides` block or `uv` command, incident steps |

Exit codes: `0` ok, `1` findings at or above `--fail-on`, `2` the scan couldn't run.

### In GitHub Actions

```yaml
name: Supply chain
on: [pull_request]
jobs:
  taintgraph:
    runs-on: ubuntu-latest
    services:
      falkordb:
        image: falkordb/falkordb:latest
        ports: ["6379:6379"]
    env:
      FALKORDB_URL: redis://localhost:6379
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
        with: { repository: kalash33/taintgraph, path: .taintgraph }
      - uses: pnpm/action-setup@v4
        with: { package_json_file: .taintgraph/package.json }
      - uses: actions/setup-node@v4
        with: { node-version: 24 }
      - run: pnpm -C .taintgraph install --frozen-lockfile
      - run: pnpm -C .taintgraph scan "$GITHUB_WORKSPACE/package-lock.json" --fail-on malware --sarif "$GITHUB_WORKSPACE/taintgraph.sarif"
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: taintgraph.sarif }
```

## MCP server

Lets a coding agent check a lockfile before it changes one:

```json
{
  "mcpServers": {
    "taintgraph": {
      "command": "pnpm",
      "args": ["-C", "/path/to/taintgraph/server", "mcp"],
      "env": { "TAINTGRAPH_ORG": "demo", "FALKORDB_URL": "redis://localhost:6380" }
    }
  }
}
```

| Tool | |
|---|---|
| `scan` | scan a local lockfile or MCP config by path, or a sample |
| `list_projects` | projects in the workspace with their verdicts |
| `ask` | ask the Analyst; returns the answer and its steps |
| `explain_package`, `trace_exposures`, `fix_plan`, `workspace_exposure`, `scan_changes`, `top_accounts`, `simulate_worm`, `mcp_servers`, `chokepoints` | the Analyst's graph tools, one-to-one |
| `record_verdict` | record a decision. An agent can confirm malware but cannot dismiss or accept it; only a person can, in the web app |

## HTTP API

JSON everywhere; the workspace comes from the `x-taintgraph-org` header (default `demo`, `[A-Za-z0-9_-]{1,64}`). Types: [`server/src/types.ts`](../server/src/types.ts).

| Method | Path | Returns |
|---|---|---|
| GET | `/api/health` | `{ ok, falkordb, llm, agent }` |
| GET | `/api/samples` | sample inputs |
| POST | `/api/scan` | body `{ sample }`, `{ filename, content }` or `{ githubUrl }`; streams `progress`, then `done { projectId }` or `error` |
| GET | `/api/projects` | projects with verdicts |
| GET | `/api/projects/:id` | summary: counts, findings with routes, top accounts, MCP servers |
| GET | `/api/projects/:id/graph` | dependency tree with infected edges, for drawing |
| GET | `/api/projects/:id/accounts` | top 25 accounts by reach |
| GET | `/api/projects/:id/teams` | maintainer teams (community detection) and the largest connected maintainer network |
| POST | `/api/projects/:id/simulate` | body `{ login, waves? }`; worm waves |
| POST | `/api/projects/:id/ask` | body `{ question, followUp? }` (`followUp`: an investigation id, to continue that conversation); streams `started`, `step`…, `answer`, `done` |
| GET | `/api/projects/:id/changes` | what changed since the previous scan, and which new versions are flagged |
| GET | `/api/projects/:id/fix` | fix plan: items, npm/pnpm/yarn overrides, Python commands, incident steps |
| GET | `/api/projects/:id/report` | `{ markdown }` |
| GET | `/api/investigations/:id` | a past investigation with steps and evidence |
| POST | `/api/findings/:id/verdict` | body `{ verdict: confirmed \| dismissed \| accepted, note? }`; may return `proposedRule` |
| GET | `/api/memory` | investigations, verdicts, rules, tasks |
| POST | `/api/rules/:id/activate` | turn a proposed rule on |
| POST | `/api/sentinel` | retro-hunt: `{ checked, newAdvisories, hits }` |

Streams are server-sent events with one JSON object per `data:` line. Errors are `{ error }` with a 4xx or 5xx status; 429 carries `Retry-After`.

```bash
curl -N -X POST localhost:8787/api/scan -H 'content-type: application/json' -d '{"sample":"chalk-2025"}'
curl -N -X POST localhost:8787/api/projects/<id>/ask -H 'content-type: application/json' \
  -d '{"question":"Which accounts could poison the most of our tree?"}'
```

## Configuration

| Variable | Default | |
|---|---|---|
| `FALKORDB_URL` | `redis://localhost:6380` | FalkorDB connection |
| `PORT` | `8787` | HTTP port |
| `GEMINI_API_KEY` / `OPENROUTER_API_KEY` / `NVIDIA_API_KEY` / `ANTHROPIC_API_KEY` | | turns on the LLM Analyst (checked in that order) |
| `GITHUB_TOKEN` | | optional; raises GitHub's rate limit for repository scans (60 an hour without it) |
| `TAINTGRAPH_SEED` | off | `1` scans the samples into an empty `demo` workspace on start |
| `LLM_MODEL` | per provider | override the model |
| `LLM_PROVIDER=openai`, `LLM_BASE_URL`, `LLM_API_KEY` | | any OpenAI-compatible endpoint (Ollama, vLLM, LM Studio) |
| `TAINTGRAPH_AUTO_LLM` | off | use the model for scan-triggered investigations too |
| `TAINTGRAPH_ORG` | `demo` | MCP server workspace |
| `TRUST_PROXY` | off | set to `1` behind a reverse proxy, so rate limits see client IPs |
