import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { mcpPackage, parseInput, pnpmResolve, splitSpec } from "../src/ingest/parsers.ts";

const fixture = (f: string) => readFileSync(new URL(`../../fixtures/${f}`, import.meta.url), "utf8");
const keys = (p: { packages: Map<string, unknown> }) => [...p.packages.keys()].sort();

test("splitSpec: scopes, versions and git URLs", () => {
  assert.deepEqual(splitSpec("@tanstack/react-router@1.169.5"), { name: "@tanstack/react-router", version: "1.169.5" });
  assert.deepEqual(splitSpec("chalk"), { name: "chalk", version: null });
  assert.deepEqual(splitSpec("foo@git+https://git@github.com/a/b.git#x"), { name: "foo", version: "git+https://git@github.com/a/b.git#x" });
});

test("package-lock: nested resolution keeps chalk 5.6.1 under lint-staged apart from hoisted chalk 4", () => {
  const p = parseInput("package-lock.json", fixture("chalk-sept-2025.package-lock.json"));
  assert.ok(p.packages.has("npm/chalk@5.6.1") && p.packages.has("npm/chalk@4.1.2"));
  assert.ok(p.edges.some((e) => e.from === "npm/lint-staged@16.1.6" && e.to === "npm/chalk@5.6.1"));
  assert.equal(p.direct.find((d) => d.key === "npm/lint-staged@16.1.6")?.dev, true);
});

test("package-lock workspaces: each workspace is a root and resolves its own node_modules first", () => {
  const lock = {
    name: "mono",
    lockfileVersion: 3,
    packages: {
      "": { name: "mono", workspaces: ["packages/*"] },
      "packages/app": { name: "app", dependencies: { lodash: "^3" }, devDependencies: { dep: "^2" } },
      "node_modules/app": { resolved: "packages/app", link: true },
      "packages/app/node_modules/lodash": { version: "3.10.1", dependencies: { dep: "^2" } },
      "packages/app/node_modules/dep": { version: "2.0.0" },
      "node_modules/dep": { version: "1.0.0" },
    },
  };
  const p = parseInput("package-lock.json", JSON.stringify(lock));
  assert.deepEqual(p.direct.map((d) => d.key).sort(), ["npm/dep@2.0.0", "npm/lodash@3.10.1"]);
  assert.ok(p.edges.some((e) => e.from === "npm/lodash@3.10.1" && e.to === "npm/dep@2.0.0"));
});

test("pnpm: aliases resolve to the real package; git and file deps are skipped", () => {
  assert.deepEqual(pnpmResolve("loader-utils2", "loader-utils@2.0.4"), { name: "loader-utils", version: "2.0.4" });
  assert.deepEqual(pnpmResolve("react", "19.0.0(react-dom@19.0.0)"), { name: "react", version: "19.0.0" });
  const lock = `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      rsdt-experimental:
        specifier: npm:react-server-dom-turbopack@0.0.0-experimental-1
        version: react-server-dom-turbopack@0.0.0-experimental-1
      foo:
        specifier: github:a/b
        version: git+https://git@github.com/a/b.git#abc
      local:
        specifier: file:../local
        version: file:../local
packages:
  react-server-dom-turbopack@0.0.0-experimental-1:
    resolution: {integrity: sha512-x}
snapshots:
  react-server-dom-turbopack@0.0.0-experimental-1: {}
`;
  assert.deepEqual(keys(parseInput("pnpm-lock.yaml", lock)), ["npm/react-server-dom-turbopack@0.0.0-experimental-1"]);
  assert.deepEqual(keys(parseInput("pnpm-lock.yaml", fixture("tanstack-may-2026.pnpm-lock.yaml"))), ["npm/@tanstack/react-router@1.169.5", "npm/@tanstack/router-core@1.169.8"]);
});

test("yarn v1 (with an alias) and Berry (with workspaces)", () => {
  const v1 = parseInput(
    "yarn.lock",
    `# yarn lockfile v1

"app-dep@^1.0.0":
  version "1.2.0"
  dependencies:
    debug "^4.3.0"

debug@^4.3.0:
  version "4.4.2"

"lu2@npm:loader-utils@2.0.4":
  version "2.0.4"
`,
  );
  assert.deepEqual(keys(v1), ["npm/app-dep@1.2.0", "npm/debug@4.4.2", "npm/loader-utils@2.0.4"]);
  assert.ok(v1.edges.some((e) => e.from === "npm/app-dep@1.2.0" && e.to === "npm/debug@4.4.2"));
  const berry = parseInput(
    "yarn.lock",
    `__metadata:
  version: 8

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."
  dependencies:
    chalk: "npm:^5.6.0"

"chalk@npm:^5.6.0":
  version: 5.6.1
  resolution: "chalk@npm:5.6.1"
`,
  );
  assert.equal(berry.name, "app");
  assert.deepEqual(berry.direct, [{ key: "npm/chalk@5.6.1", dev: false }]);
});

test("bun.lock: trailing commas, nested overrides, all workspaces are roots", () => {
  const p = parseInput(
    "bun.lock",
    `{
  "lockfileVersion": 1,
  "workspaces": { "": { "name": "mono", "dependencies": { "a": "^1" } }, "packages/web": { "name": "web", "devDependencies": { "b": "^2" } }, },
  "packages": {
    "a": ["a@1.0.0", "", { "dependencies": { "c": "^1" } }, "sha"],
    "b": ["b@2.0.0", "", {}, "sha"],
    "c": ["c@1.5.0", "", {}, "sha"],
    "a/c": ["c@1.0.0", "", {}, "sha"],
  },
}`,
  );
  assert.ok(p.edges.some((e) => e.from === "npm/a@1.0.0" && e.to === "npm/c@1.0.0"));
  assert.deepEqual(p.direct, [{ key: "npm/a@1.0.0", dev: false }, { key: "npm/b@2.0.0", dev: true }]);
});

test("uv.lock, poetry.lock and requirements.txt", () => {
  const uv = parseInput("uv.lock", fixture("litellm-mar-2026.uv.lock"));
  assert.equal(uv.name, "support-agent");
  assert.ok(uv.edges.some((e) => e.from === "pypi/dspy@3.0.3" && e.to === "pypi/litellm@1.82.8"));
  assert.deepEqual(uv.direct.map((d) => d.key).sort(), ["pypi/dspy@3.0.3", "pypi/num2words@0.5.15", "pypi/requests@2.19.0"]);
  const poetry = parseInput(
    "poetry.lock",
    `[[package]]
name = "Requests"
version = "2.19.0"
[package.dependencies]
urllib3 = ">=1.21"

[[package]]
name = "urllib3"
version = "1.23"
`,
  );
  assert.deepEqual(poetry.direct, [{ key: "pypi/requests@2.19.0", dev: false }]);
  const req = parseInput("requirements.txt", "litellm==1.82.7\nNum2Words[x]==0.5.15  # pinned\nflask>=2\n-r other.txt\n");
  assert.deepEqual(keys(req), ["pypi/litellm@1.82.7", "pypi/num2words@0.5.15"]);
  assert.match(req.source, /1 unpinned line skipped/);
});

test("MCP configs: npm and PyPI launchers, pinning, remote servers", () => {
  assert.deepEqual(mcpPackage("npx", ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]), { ecosystem: "npm", spec: "@modelcontextprotocol/server-filesystem" });
  assert.deepEqual(mcpPackage("pnpm", ["dlx", "mcp-remote@0.1.15"]), { ecosystem: "npm", spec: "mcp-remote@0.1.15" });
  assert.deepEqual(mcpPackage("uvx", ["--from", "mcp-server-fetch==1.0", "fetch"]), { ecosystem: "PyPI", spec: "mcp-server-fetch==1.0" });
  assert.deepEqual(mcpPackage("docker", ["run", "x"]), { ecosystem: null, spec: null });
  const p = parseInput("claude-code.mcp.json", fixture("claude-code.mcp.json"));
  const s = Object.fromEntries(p.mcp.map((m) => [m.name, m]));
  assert.equal(p.kind, "agent-config");
  assert.equal(s.filesystem.pinned, false);
  assert.equal(s["remote-tools"].version, "0.1.15");
  assert.equal(s.fetch.ecosystem, "PyPI");
  assert.equal(s.linear.ecosystem, null);
});

test("unreadable input gets a helpful message", () => {
  assert.throws(() => parseInput("notes.md", "hello"), /Upload a package-lock.json/);
  assert.throws(() => parseInput("notes.txt", "hello"), /No pinned packages/);
  assert.throws(() => parseInput("bun.lockb", "\0"), /binary/);
});

test("uv.lock: packages from git, a URL or another index aren't treated as PyPI packages", () => {
  const lock = `version = 1
[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "requests" }, { name = "torch" }, { name = "mylib" }]

[[package]]
name = "requests"
version = "2.32.3"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "torch"
version = "2.5.1+cpu"
source = { registry = "https://download.pytorch.org/whl/cpu" }

[[package]]
name = "mylib"
version = "1.0.0"
source = { git = "https://github.com/acme/mylib?rev=abc#abc" }
`;
  const r = parseInput("uv.lock", lock);
  assert.deepEqual([...r.packages.values()].map((x) => x.key), ["pypi/requests@2.32.3"]);
});

test("pnpm 11+: a lockfile with two YAML documents uses the project document, not the package manager one", () => {
  const lock = [
    "---", "lockfileVersion: '9.0'", "importers:", "  .:", "    packageManagerDependencies:", "      pnpm:", "        specifier: 12.11.2", "        version: 12.11.2",
    "packages:", "  pnpm@12.11.2:", "    resolution: {integrity: sha512-x}", "snapshots:", "  pnpm@12.11.2: {}",
    "---", "lockfileVersion: '9.0'", "importers:", "  .:", "    dependencies:", "      chalk:", "        specifier: 5.6.1", "        version: 5.6.1",
    "packages:", "  chalk@5.6.1:", "    resolution: {integrity: sha512-y}", "snapshots:", "  chalk@5.6.1: {}", "",
  ].join("\n");
  const r = parseInput("pnpm-lock.yaml", lock);
  assert.deepEqual([...r.packages.values()].map((x) => x.key), ["npm/chalk@5.6.1"]);
});

test("yarn v1: local link:/file: packages are not registry packages", () => {
  const lock = ["# yarn lockfile v1", "", "\"eslint-plugin-react-internal@link:./scripts/eslint-rules\":", "  version \"0.0.0\"", "  uid \"\"", "", "chalk@^5.6.0:", "  version \"5.6.1\"", "  resolved \"https://registry.yarnpkg.com/chalk/-/chalk-5.6.1.tgz\"", ""].join("\n");
  assert.deepEqual([...parseInput("yarn.lock", lock).packages.values()].map((x) => x.key), ["npm/chalk@5.6.1"]);
});
