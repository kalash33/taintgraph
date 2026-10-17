import { config } from "../config.ts";
import { parseInput } from "./parsers.ts";

// Find a scannable file in a public GitHub repository: a lockfile or an MCP config, at the root or in a subfolder
// (monorepos keep them in apps/web or frontend/). Links to a folder (/tree/branch/dir) or a file (/blob/branch/file) work too.

const LOCKFILES = ["pnpm-lock.yaml", "package-lock.json", "yarn.lock", "bun.lock", "uv.lock", "poetry.lock", "requirements.txt"];
const MCP_CONFIGS = [".mcp.json", "claude_desktop_config.json", ".cursor/mcp.json", ".vscode/mcp.json"];
const EXCLUDE = /(^|\/)(node_modules|vendor|\.yarn)\//;
const LATER = /(^|\/)(fixtures?|__fixtures__|tests?|testdata|examples?|e2e|benchmarks?|docs?)\//i; // considered only after everything else
const MAX = 25 * 1024 * 1024;

export interface RepoFile {
  filename: string;
  content: string;
  name: string; // project name: owner/repo, plus the folder when it isn't the root
  path: string; // path inside the repository
  others: string[]; // other scannable files that were found
}

const headers = () => ({
  "user-agent": config.userAgent,
  accept: "application/vnd.github+json",
  ...(process.env.GITHUB_TOKEN ? { authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}),
});

export function parseRepoUrl(url: string): { owner: string; repo: string; ref?: string; path?: string } {
  const m = url.trim().match(/^https?:\/\/(?:www\.)?github\.com\/([\w.-]+)\/([\w.-]+?)(?:\.git)?(?:\/(tree|blob)\/([^/]+)(?:\/(.+?))?)?\/?(?:[?#].*)?$/);
  if (!m) throw Object.assign(new Error("Paste a GitHub repository URL like https://github.com/owner/repo"), { statusCode: 400 });
  return { owner: m[1], repo: m[2], ref: m[4], path: m[5] };
}

/** Lower is better: the root before subfolders, shallow before deep, lockfiles in LOCKFILES order. */
export function rank(path: string): number {
  const base = path.split("/").pop()!;
  const mcp = MCP_CONFIGS.findIndex((c) => path === c || path.endsWith(`/${c}`));
  const type = mcp >= 0 ? LOCKFILES.length + mcp : LOCKFILES.indexOf(base);
  // The app's own lockfiles come before MCP configs, at any depth.
  return (LATER.test(path) ? 10_000 : 0) + (mcp >= 0 ? 5_000 : 0) + (path.split("/").length - 1) * 100 + type;
}

export function candidates(paths: string[], within = ""): string[] {
  const prefix = within ? within.replace(/\/$/, "") + "/" : "";
  return paths
    .filter((p) => p.startsWith(prefix))
    .filter((p) => !EXCLUDE.test(p))
    .filter((p) => LOCKFILES.includes(p.split("/").pop()!) || MCP_CONFIGS.some((c) => p === c || p.endsWith(`/${c}`)))
    .sort((a, b) => rank(a.slice(prefix.length)) - rank(b.slice(prefix.length)));
}

export function parentLockfiles(paths: string[], dir: string): string[] {
  const parts = dir.replace(/\/$/, "").split("/");
  for (let i = parts.length - 1; i >= 0; i--) {
    const up = parts.slice(0, i).join("/");
    const here = paths.filter((p) => (up ? p.startsWith(up + "/") : true) && !p.slice(up ? up.length + 1 : 0).includes("/") && LOCKFILES.includes(p.split("/").pop()!));
    if (here.length) return here.sort((a, b) => rank(a) - rank(b));
  }
  return [];
}

async function json(url: string) {
  const res = await fetch(url, { headers: headers(), signal: AbortSignal.timeout(20_000) });
  if (res.status === 403 || res.status === 429) throw new Error("GitHub's rate limit for anonymous requests was reached. Try again later, or set GITHUB_TOKEN on the server.");
  return res;
}

export async function githubFile(url: string): Promise<RepoFile> {
  const { owner, repo, ref, path } = parseRepoUrl(url);
  const meta = await json(`https://api.github.com/repos/${owner}/${repo}`);
  if (!meta.ok) throw new Error(`GitHub returned ${meta.status} for ${owner}/${repo}. Is the repository public?`);
  const branch = ref ?? ((await meta.json()) as any).default_branch ?? "main";

  const tree = await json(`https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`);
  if (!tree.ok) throw new Error(`GitHub returned ${tree.status} for the ${branch} branch of ${owner}/${repo}.`);
  const all = (((await tree.json()) as any).tree ?? []).filter((e: any) => e.type === "blob").map((e: any) => e.path as string);
  // A link straight to a file scans that file; a link to a folder looks inside it.
  let list = path && all.includes(path) ? [path] : candidates(all, path);
  // A workspace package (apps/web) usually has no lockfile of its own: use the nearest one above it, like the package manager does.
  if (!list.length && path) list = parentLockfiles(all, path);
  if (!list.length)
    throw new Error(`No lockfile or MCP config in ${owner}/${repo}${path ? `/${path}` : ""}. Supported: ${LOCKFILES.join(", ")}, and MCP configs (${MCP_CONFIGS.join(", ")}).`);

  const tried: string[] = [];
  for (const p of list.slice(0, 6)) {
    const res = await fetch(`https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(branch)}/${p.split("/").map(encodeURIComponent).join("/")}`, {
      signal: AbortSignal.timeout(30_000),
    });
    if (!res.ok) continue;
    if (Number(res.headers.get("content-length") ?? 0) > MAX) throw new Error(`${p} in ${owner}/${repo} is larger than 25 MB.`);
    const content = await res.text();
    const filename = p.split("/").pop()!;
    try {
      parseInput(filename, content); // e.g. a requirements.txt with no pinned versions: try the next file
    } catch {
      tried.push(p);
      continue;
    }
    const dir = p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "";
    return { filename, content, name: dir ? `${owner}/${repo}/${dir}` : `${owner}/${repo}`, path: p, others: list.filter((x) => x !== p).slice(0, 10) };
  }
  throw new Error(`Found ${tried.length ? tried.join(", ") : list.slice(0, 3).join(", ")} in ${owner}/${repo}, but none has pinned versions Taintgraph can read. Commit a lockfile, or pin requirements with ==.`);
}
