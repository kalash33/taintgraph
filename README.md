# Upstream

**Find out how a software supply-chain compromise reaches your app, and which accounts could poison it next.**

Give Upstream a lockfile (npm, pnpm, yarn, bun, uv, poetry, pip) or an AI tool's MCP config. It builds a FalkorDB graph of every installed version, who can publish it, which advisories touch it and how releases changed, then:

- traces the exact route from your project to each malicious or vulnerable version, through *your* dependency edges only
- ranks the maintainer accounts that could poison the largest share of your tree (PageRank) and simulates a Shai-Hulud style worm spreading from one of them
- flags tampered releases: removed from the registry, new publisher plus a new install script, dropped provenance, typosquats, unpinned MCP servers
- lets an **Analyst agent** answer questions from the graph with fixed read-only Cypher tools, showing each step, the query it ran and the evidence subgraph
- **remembers**: human verdicts, past investigations and learned triage rules live in the graph and change the next scan
- hands work between agents (**Scout → Analyst → Reporter**) through Task nodes, and a **Sentinel** retro-hunts new advisories against every version any project ever installed

Built for **Graph Hacks: Context for AI Agents** (WeMakeDevs × FalkorDB, Oct 15–18 2026).
Tracks: **01 Agents That Act on Connected Data** and **02 Agent Memory and Coordination**.

## Try it in two minutes

```bash
git clone https://github.com/kalash33/upstream && cd upstream
cp .env.example .env          # optional: add an OpenRouter or NVIDIA key for the LLM analyst
docker compose up --build     # FalkorDB + Upstream
open http://localhost:8787    # click a sample, e.g. "chalk and debug, September 2025"
```

No API key is needed. Without one, a built-in investigator answers with the same tools.

Without Docker for the app (Node 24, pnpm 10):

```bash
docker compose up -d falkordb
pnpm install && pnpm build
pnpm start                     # http://localhost:8787
pnpm test                      # 28 tests; integration tests run against the local FalkorDB
```

The samples are real incidents rebuilt as lockfiles:

| Sample | What Upstream finds |
|---|---|
| chalk and debug, Sept 2025 (a real public lockfile) | 6 versions from the phished-maintainer campaign, all under `lint-staged`, each with its route |
| debug 4.4.2 in another extension | the same campaign in a second project. A verdict given in the first project doesn't hide it here |
| TanStack, May 2026 (pnpm) | `@tanstack/react-router` from the hijacked trusted-publishing release |
| LiteLLM, March 2026 (uv.lock) | `litellm@1.82.8` arriving through `dspy` |
| Typosquats | `lodahs` (malware, now an npm security placeholder) and `expres` |
| Claude Code MCP setup | `mcp-remote` with a command-injection advisory, unpinned `npx`/`uvx` servers |

## Graph model

One graph per workspace (`up:org:<name>`, picked with the `x-upstream-org` header), so tenants are isolated by the graph boundary rather than by a WHERE clause.

```
(:Project)-[:DEPENDS_ON {dev}]->(:Version)                      direct dependencies
(:Version)-[:DEPENDS_ON {projects:[ids]}]->(:Version)           resolved tree; each edge lists the projects that declared it
(:Version)-[:OF]->(:Package {typosquat_of, downloads, dependents})
(:Version)-[:PRECEDES]->(:Version)                              previous release -> this one
(:Account {kind: user|org|workflow})-[:MAINTAINS]->(:Package)
(:Account)-[:PUBLISHED]->(:Version)                             who actually pushed the release (or the CI identity)
(:Advisory {kind: malware|vuln})-[:AFFECTS {explicit, fixed, first_seen}]->(:Version)
(:Scan)-[:OF_PROJECT]->(:Project),  (:Scan)-[:SAW {dev}]->(:Version)   point-in-time snapshot
(:McpServer {pinned, command})-[:DECLARED_IN]->(:Project),  (:McpServer)-[:RUNS]->(:Version)

Memory and coordination
(:Finding {signal, severity, status, path})-[:ABOUT]->(:Version), -[:IN_PROJECT]->(:Project), -[:EVIDENCE]->(:Advisory)
(:Investigation)-[:ABOUT_PROJECT]->(:Project), -[:HAS_STEP]->(:Step)-[:NEXT]->(:Step), -[:CONCLUDED]->(:Finding)
(:Rule {when, then, status, confidence})-[:LEARNED_FROM]->(:Finding)
(:Task {type, for_agent, status, claimed_by})-[:FOR_PROJECT]->(:Project)
```

Version properties include `published_at`, `has_install_script`, `install_scripts`, `has_provenance`, `removed` and `rank` (PageRank). Keys look like `npm/chalk@5.6.1`, `pypi/litellm@1.82.8`, `npm-user/qix` and `pypi-org/<org>`.

Why a graph: the question is always a path. *Project → lint-staged → listr2 → log-update → strip-ansi → ansi-regex ← MAL advisory ← published by a phished account → which maintains 40 other packages in my tree.* Edges carry the per-project scope, so two projects that share `chalk@5.6.1` never borrow each other's routes.

## Cypher

All 65 queries are plain files in [`queries/`](queries). Nothing is generated at runtime. Some highlights:

| Query | What it does |
|---|---|
| [`exposure_paths`](queries/exposure_paths.cypher) | `shortestPath` from the project to every advisory-hit version, plus whether the route uses only this project's edges |
| [`version_routes`](queries/version_routes.cypher) | `allShortestPaths` to one version, filtered to the project's edges |
| [`algo_pagerank`](queries/algo_pagerank.cypher) / [`algo_chokepoints`](queries/algo_chokepoints.cypher) | `algo.pageRank` over DEPENDS_ON for account weights; `algo.betweenness` for chokepoints |
| [`accounts_reach`](queries/accounts_reach.cypher) | `CALL { … UNION … }` of maintainers and publishers: everything one login can publish into this tree |
| [`worm_wave`](queries/worm_wave.cypher) | one worm wave: poisoned versions, then the maintainers of their dependents |
| [`release_facts`](queries/release_facts.cypher) | publisher, install-script and provenance changes against the previous release |
| [`point_in_time`](queries/point_in_time.cypher) | "were we exposed on 2025-09-08, and was the advisory public yet?" |
| [`advisories_search`](queries/advisories_search.cypher) | full-text index over advisory summaries |
| [`investigation_step`](queries/investigation_step.cypher) | writes each agent step and links it to the previous one with NEXT |
| [`task_claim`](queries/task_claim.cypher) | atomic task claim between agents |

Things learned about FalkorDB 6 along the way, and handled in the queries: `shortestPath` is only allowed in WITH/RETURN. Repeating an anonymous `(:Scan {id})` pattern can return nothing, so it is bound once. After an UNWIND, a WHERE on an OPTIONAL MATCH drops rows, so those filters are CASE expressions.

## The agents

| Agent | Job | Code |
|---|---|---|
| Scout | parse → OSV.dev, npm, PyPI, deps.dev, ecosyste.ms → write the graph → PageRank → triage → leave an `analyze` task | [`ingest/scout.ts`](server/src/ingest/scout.ts) |
| Analyst | claim the task or answer a person; memory first, then tools | [`agents/analyst.ts`](server/src/agents/analyst.ts) |
| Reporter | turn the graph and the Analyst's conclusion into an incident report | [`agents/reporter.ts`](server/src/agents/reporter.ts) |
| Sentinel | re-check every observed version against OSV, link new advisories, re-triage, re-queue | [`agents/sentinel.ts`](server/src/agents/sentinel.ts) |

The Analyst follows the event guide on agents that reason over a graph:

- **Fixed tools, never text-to-Cypher.** Nine parameterized queries ([`agents/tools.ts`](server/src/agents/tools.ts)) all run through `GRAPH.RO_QUERY`, so the agent cannot write.
- **Names are resolved against the graph first.** A misspelt package or login returns `unknown_name` with "did you mean" suggestions from edit distance.
- **Typed outcomes:** `answered`, `from_memory`, `not_in_graph`, `unknown_name`. The UI shows which kind each answer is.
- **The answer is checked.** Every `name@version` or backticked name in the model's answer must appear in what the tools returned. If one doesn't, the answer is rebuilt from the tool results and marked as rebuilt.
- **Every step is persisted** (tool, input, Cypher, outcome, evidence subgraph) as `Step` nodes, and the UI draws the evidence.

### Memory

- **Semantic.** A human verdict (real threat / not a threat / risk accepted) is stored on the Finding. When the same version shows up in another project, the verdict is recalled as context. Compromise signals (malware, possible malware, removed from the registry) are **never skipped automatically**: the finding stays open with a note.
- **Procedural.** After two matching verdicts for a signal, a Rule is *proposed* (e.g. typosquat → skip). It acts only after a person activates it, and never on compromise signals.
- **Episodic.** Investigations and their conclusions are recalled. Asking the same question again after the same scan is answered `from_memory` with no new queries.

## LLM configuration

The Analyst works with any OpenAI-compatible endpoint, or Anthropic. Set one of these in `.env`:

```bash
OPENROUTER_API_KEY=...        # default model openai/gpt-oss-120b
NVIDIA_API_KEY=...            # build.nvidia.com, default model openai/gpt-oss-120b
ANTHROPIC_API_KEY=...
LLM_MODEL=...                 # override the model
LLM_PROVIDER=openai LLM_BASE_URL=http://localhost:11434/v1 LLM_MODEL=qwen3:32b   # Ollama, vLLM, LM Studio…
```

The client retries on 429 (honouring Retry-After), 5xx and network errors, and on 200 responses that carry an error body. It accepts tool arguments as strings, objects or broken JSON, fills in missing call ids, strips `<think>` blocks, and passes OpenRouter `reasoning_details` back unchanged. If the model fails mid-investigation, the built-in investigator finishes from the graph. Automatic handoff investigations use the built-in investigator unless `UPSTREAM_AUTO_LLM=1`, so scans don't spend credits.

## CLI and CI

```bash
pnpm scan path/to/package-lock.json
pnpm scan https://github.com/owner/repo --fail-on malware --sarif upstream.sarif
pnpm scan chalk-2025 --ask "What if qix is phished?"
```

Exit codes: `0` ok, `1` an open finding at or above `--fail-on` (malware | critical | high | medium), `2` the scan couldn't run. SARIF 2.1.0 output uploads to GitHub code scanning.

## MCP server

A coding agent can use Upstream before touching a lockfile:

```json
{ "mcpServers": { "upstream": { "command": "pnpm", "args": ["-C", "/path/to/upstream/server", "mcp"], "env": { "UPSTREAM_ORG": "demo" } } } }
```

Tools: `scan`, `list_projects`, `ask`, `explain_package`, `trace_exposures`, `top_accounts`, `simulate_worm`, `mcp_servers`, `chokepoints`, `record_verdict`. An agent can confirm a malware finding but can't dismiss or accept one. Only a person can, in the web app.

## API

`GET /api/health`, `/api/samples`, `/api/projects`, `/api/projects/:id`, `/api/projects/:id/graph`, `/api/projects/:id/accounts`, `/api/projects/:id/report`, `/api/investigations/:id`, `/api/memory` ·
`POST /api/scan` (SSE), `/api/projects/:id/ask` (SSE), `/api/projects/:id/simulate`, `/api/findings/:id/verdict`, `/api/rules/:id/activate`, `/api/sentinel`.
The full contract is in [`server/src/types.ts`](server/src/types.ts). Workspace: header `x-upstream-org`.

## Security notes

- Agent tools are read-only (`GRAPH.RO_QUERY`) and parameterized; user text is never spliced into Cypher. Full-text search input is reduced to plain words.
- Text written by package authors (install scripts, advisory summaries) is treated as untrusted: control and bidi characters are stripped, it is length-limited, and the model is told it's data, not instructions.
- FalkorDB is bound to 127.0.0.1 in `docker-compose.yml`. Put a password on it before exposing it anywhere.
- Rate limits per IP; errors don't leak internals.

## Layout

```
queries/         every Cypher query, one file each
server/src/      ingest/ (parsers, feeds, heuristics, scout) · agents/ · analysis.ts · memory.ts · index.ts (API) · mcp.ts · cli.ts
server/test/     parsers, heuristics, LLM adapter, integration (real FalkorDB)
web/             Vite + React UI: dependency graph, findings, accounts, worm simulation, Ask with steps and evidence, memory
fixtures/        sample lockfiles
```

## How this was built

Built during the hackathon window with an AI coding assistant (Claude Code). The idea, graph-model sketches and research were prepared before the event, as the rules allow. All code in this repository was written during the event; the commit history shows it. See [`docs/PLAN.md`](docs/PLAN.md).

Data: [OSV.dev](https://osv.dev), the npm registry, PyPI, [deps.dev](https://deps.dev), [ecosyste.ms](https://ecosyste.ms). Graph: [FalkorDB](https://falkordb.com).

## License

MIT
