# Security

## Reporting a vulnerability

Please open a private security advisory on GitHub (Security → Report a vulnerability) instead of a public issue. Include steps to reproduce and the version or commit you tested.

## How Taintgraph protects itself

Taintgraph reads data written by package authors, and some of those authors are attackers. It is built on that assumption.

- **Agents can't write.** Every Analyst tool is a fixed, parameterized query run with `GRAPH.RO_QUERY`. User and model text is passed as parameters, never spliced into Cypher. Full-text search input is reduced to plain words.
- **Untrusted text is defused.** Install scripts, advisory summaries and notes are stripped of control and bidirectional-override characters and length-limited before they reach the UI or a model. The model is told that tool results are data, not instructions.
- **Answers are checked.** A model answer that names a package the graph didn't return is replaced with one built from the graph.
- **Memory can't hide malware or severe bugs.** Learned rules and earlier verdicts never auto-skip a compromise signal, and a skip rule never hides a critical or high finding. Over MCP, an agent cannot dismiss or accept a malware finding.
- **Text from scanned files is data.** Project and MCP server names are sanitized and length-limited, and the model gets them as quoted data.
- **A rescan is all or nothing.** Readers keep using the last fully triaged scan until the new one finishes, so a failed or in-progress scan never shows a compromised project as clean.
- **Bounded inputs.** Uploads are capped at 25 MB; GitHub fetches are limited to github.com with timeouts; every feed request has a timeout.
- **Rate limits** per IP on scans, questions and writes. Errors don't expose internals.
- **Workspaces are separate graphs.** One workspace's queries can't see another's.

## Running it safely

- FalkorDB has no password by default. `docker-compose.yml` binds it to `127.0.0.1`. Set `REDIS_ARGS="--requirepass …"` and put the password in `FALKORDB_URL` before exposing it anywhere.
- The workspace header separates tenants but does not authenticate them. Put Taintgraph behind your own auth (a reverse proxy or an identity-aware proxy) before sharing it.
- Keep API keys in `.env`, which is git-ignored.
