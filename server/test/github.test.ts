import { test } from "node:test";
import assert from "node:assert/strict";
import { candidates, parseRepoUrl } from "../src/ingest/github.ts";

test("GitHub links: repo, folder, file", () => {
  assert.deepEqual(parseRepoUrl("https://github.com/owner/repo"), { owner: "owner", repo: "repo", ref: undefined, path: undefined });
  assert.deepEqual(parseRepoUrl("https://github.com/owner/repo.git"), { owner: "owner", repo: "repo", ref: undefined, path: undefined });
  assert.deepEqual(parseRepoUrl("https://github.com/owner/repo/tree/main/apps/web"), { owner: "owner", repo: "repo", ref: "main", path: "apps/web" });
  assert.deepEqual(parseRepoUrl("https://github.com/owner/repo/blob/dev/frontend/package-lock.json?plain=1"), { owner: "owner", repo: "repo", ref: "dev", path: "frontend/package-lock.json" });
  assert.throws(() => parseRepoUrl("https://gitlab.com/owner/repo"));
  assert.throws(() => parseRepoUrl("https://github.com/owner"));
});

test("lockfiles: root first, then the shallowest folder; MCP configs after lockfiles; examples and tests last", () => {
  const tree = ["README.md", "examples/demo/package-lock.json", "apps/web/pnpm-lock.yaml", "node_modules/x/package-lock.json", "services/api/deep/uv.lock", "apps/api/requirements.txt", ".cursor/mcp.json"];
  assert.deepEqual(candidates(tree), ["apps/web/pnpm-lock.yaml", "apps/api/requirements.txt", "services/api/deep/uv.lock", ".cursor/mcp.json", "examples/demo/package-lock.json"]);
  assert.deepEqual(candidates([...tree, "package-lock.json"])[0], "package-lock.json");
  assert.deepEqual(candidates(tree, "services/api"), ["services/api/deep/uv.lock"]);
  assert.deepEqual(candidates(["docs/package-lock.json"]), ["docs/package-lock.json"], "a lockfile only in docs/ is still found");
});

test("a workspace folder without its own lockfile uses the nearest one above it", async () => {
  const { parentLockfiles } = await import("../src/ingest/github.ts");
  const tree = ["pnpm-lock.yaml", "web/package.json", "web/src/App.tsx", "services/api/uv.lock", "services/api/app/main.py"];
  assert.deepEqual(parentLockfiles(tree, "web"), ["pnpm-lock.yaml"]);
  assert.deepEqual(parentLockfiles(tree, "services/api/app"), ["services/api/uv.lock"]);
  assert.deepEqual(parentLockfiles(["README.md"], "web"), []);
});
