# Build plan (Oct 15-18, 2026, IST)

## Product
Upstream turns a lockfile (npm or PyPI) or an AI tool's MCP config into a FalkorDB graph:
project -> package versions -> packages -> maintainer/publisher accounts, plus malware and vulnerability
advisories from OSV. An analyst agent answers questions with fixed, read-only Cypher tools, shows the
path behind every answer, remembers human verdicts, and learns triage rules.

## Principles (from the event guide, "How to build an agent that reasons over a graph")
- The agent never writes Cypher: every tool is a human-written, parameterized query run with `ro_query`.
- Names are resolved against the graph before a tool runs (unknown package -> typed "unknown" outcome).
- Answers are typed: answered with a path / answered from memory / not in the graph / unknown name.
- The model's sentence is checked: every package or account it names must appear in the tool results,
  otherwise the answer falls back to a sentence built from the rows.
- One graph per tenant; memory lives in the graph next to the facts it is about.

## Days
- **Day 1 (Oct 15-16):** repo, FalkorDB, graph model + indexes, lockfile parsers (package-lock, pnpm, yarn,
  bun, uv, poetry, requirements, MCP configs), public feeds with caching (OSV, npm, PyPI, deps.dev,
  ecosyste.ms), Scout ingest, triage (malware/vuln routes + release signals), unit tests.
- **Day 2 (Oct 17):** identities + PageRank blast radius, worm simulation, analyst tools + typed outcomes +
  answer validation, LLM loop (OpenRouter / NVIDIA / Anthropic) with deterministic fallback, memory
  (verdicts, rules, episodes), task handoff, sentinel, MCP server, CLI with SARIF, API.
- **Day 3 (Oct 18):** web UI, end-to-end tests, stress test, deploy, README (graph model, queries), demo
  video, submit before 9 PM IST.
