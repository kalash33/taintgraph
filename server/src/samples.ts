import { readFileSync } from "node:fs";
import { join } from "node:path";
import { paths } from "./config.ts";
import type { Sample } from "./types.ts";

export const SAMPLES: (Sample & { name: string })[] = [
  {
    id: "chalk-2025",
    title: "chalk and debug, September 2025",
    description: "A real public VS Code extension (lperry65/Aider-Chat) whose lockfile still pins chalk 5.6.1 and five more packages from the phished-maintainer compromise, deep under lint-staged.",
    filename: "chalk-sept-2025.package-lock.json",
    name: "aider-extension",
  },
  {
    id: "debug-2025",
    title: "debug 4.4.2 in another extension",
    description: "Another real public lockfile (FinnLeh/vs-code-obsidian) that caught debug 4.4.2 and chalk 5.6.1 from the same campaign.",
    filename: "debug-sept-2025.package-lock.json",
    name: "vs-code-obsidian",
  },
  {
    id: "tanstack-2026",
    title: "TanStack, May 2026",
    description: "A pnpm lockfile pinning @tanstack/react-router 1.169.5, one of 84 malicious versions published in six minutes with a hijacked trusted-publishing token.",
    filename: "tanstack-may-2026.pnpm-lock.yaml",
    name: "tanstack-start-app",
  },
  {
    id: "litellm-2026",
    title: "LiteLLM, March 2026 (Python)",
    description: "A Python agent app (uv.lock) that gets litellm 1.82.8 through dspy. That release ran a credential stealer on every Python startup.",
    filename: "litellm-mar-2026.uv.lock",
    name: "support-agent",
  },
  {
    id: "typosquat",
    title: "Typosquats: lodahs and expres",
    description: "Two real npm look-alikes: lodahs (malware, now an npm security placeholder) and expres, one keystroke from express.",
    filename: "typosquat.package-lock.json",
    name: "checkout-service",
  },
  {
    id: "mcp",
    title: "A Claude Code MCP setup",
    description: "Six MCP servers an AI tool launches on startup: some unpinned, one pinned to mcp-remote 0.1.15 with a known command-injection flaw.",
    filename: "claude-code.mcp.json",
    name: "Claude Code MCP setup",
  },
];

export function loadSample(id: string) {
  const s = SAMPLES.find((x) => x.id === id);
  if (!s) throw Object.assign(new Error(`Unknown sample "${id}".`), { statusCode: 404 });
  return { filename: s.filename, content: readFileSync(join(paths.fixtures, s.filename), "utf8"), name: s.name };
}
