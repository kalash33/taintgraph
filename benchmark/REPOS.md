# Real repositories

Popular public repositories scanned straight from their GitHub URL (`pnpm scan https://github.com/owner/repo`), cold cache, on 2026-10-17. The point: real lockfiles of every kind parse, large monorepos finish in about two minutes, and nothing is called *compromised* unless it is.

| Repository | Lockfile picked | Versions | Verdict | Why |
|---|---|---|---|---|
| [lperry65/Aider-Chat](https://github.com/lperry65/Aider-Chat) | `package-lock.json` | 435 | **compromised** | still pins chalk 5.6.1 and five more packages from the September 2025 attack |
| [FinnLeh/vs-code-obsidian](https://github.com/FinnLeh/vs-code-obsidian) | `package-lock.json` | 389 | **compromised** | same campaign: chalk 5.6.1 and debug 4.4.2 |
| [facebook/react](https://github.com/facebook/react) | `yarn.lock` (v1) | 2,388 | vulnerable | critical CVEs in old build tooling, e.g. `@babel/traverse` 7.8.3 (code execution while compiling crafted code) |
| [withastro/astro](https://github.com/withastro/astro) | `pnpm-lock.yaml` | 2,198 | vulnerable | known CVEs only |
| [langchain-ai/langchainjs](https://github.com/langchain-ai/langchainjs) | `pnpm-lock.yaml` | 1,997 | suspicious | `langsmith` 0.11.0 was published 43 hours before the scan (fresh release) |
| [vitejs/vite](https://github.com/vitejs/vite) | `pnpm-lock.yaml` (pnpm 11, two YAML documents) | 1,259 | vulnerable | known CVEs only |
| [vercel/ai-chatbot](https://github.com/vercel/ai-chatbot) | `pnpm-lock.yaml` | 885 | vulnerable | known CVEs only |
| [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) | `package-lock.json` | 395 | vulnerable | `braces` 3.0.3 |
| [microsoft/TypeScript](https://github.com/microsoft/TypeScript) | `package-lock.json` | 239 | clean | |
| [fastapi/fastapi](https://github.com/fastapi/fastapi) | `uv.lock` | 207 | vulnerable | known CVEs only |
| [langchain-ai/langchain](https://github.com/langchain-ai/langchain) | `libs/core/uv.lock` (monorepo: picked from six) | 206 | suspicious | fresh `langsmith` release |
| [pallets/flask](https://github.com/pallets/flask) | `uv.lock` | 78 | vulnerable | known CVEs only |
| [oven-sh/bun](https://github.com/oven-sh/bun) | `bun.lock` | 42 | vulnerable | known CVEs only |
| [kalash33/taintgraph](https://github.com/kalash33/taintgraph) | `pnpm-lock.yaml` | 297 | clean | this project |

## Bugs these scans found (all fixed, each with a test)

- **Vite's lockfile wasn't read.** pnpm 11 writes two YAML documents (the package manager's own lockfile first), so the scan fell back to a test fixture. Now the project document is used, and test, fixture and playground folders rank last.
- **React was wrongly called compromised, twice.**
  - Its local `eslint-plugin-react-internal` (`link:` in yarn.lock) shares a name with a malicious npm package; local packages are now skipped.
  - A Babel CVE that mentions "malicious code" (meaning attacker input) was read as malware; the wording rule now needs shipped-malware phrasing ("embedded malicious", "contained malicious", "malicious package", "crypto miner", "backdoor").
- **Large repos were slow.** Package-reach lookups ran one after another; parallel requests cut that stage about 3× (a cold 885-version scan: 41 s).

Verdicts for live repositories change as they update their lockfiles and as new advisories appear.
