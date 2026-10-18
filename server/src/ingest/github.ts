import { config } from "../config.ts";
import { parseInput } from "./parsers.ts";

// Find a scannable file in a public GitHub repository: a lockfile or an MCP config, at the root or in a subfolder
// (monorepos keep them in apps/web or frontend/). Links to a folder (/tree/branch/dir) or a file (/blob/branch/file) work too.

const LOCKFILES = ["pnpm-lock.yaml", "package-lock.json", "yarn.lock", "bun.lock", "uv.lock", "poetry.lock", "requirements.txt"];
const MCP_CONFIGS = [".mcp.json", "claude_desktop_config.json", ".cursor/mcp.json", ".vscode/mcp.json"];
const EXCLUDE = /(^|\/)(node_modules|vendor|\.yarn)\//;
const LATER = /(^|\/)(fixtures?|__fixtures__|__tests__|__mocks__|tests?|testdata|test-fixtures|examples?|samples?|playgrounds?|e2e|benchmarks?|docs?)\//i; // considered only after everything else
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
  if (!m) throw fail("Paste a GitHub repository URL like https://github.com/owner/repo");
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

const fail = (message: string, statusCode = 400) => Object.assign(new Error(message), { statusCode });

/** Read a response body, stopping at MAX bytes even without a content-length header. */
async function capped(res: Response, what: string): Promise<string> {
  if (Number(res.headers.get("content-length") ?? 0) > MAX) throw fail(`${what} is larger than 25 MB.`, 413);
  const reader = res.body!.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > MAX) {
      await reader.cancel();
      throw fail(`${what} is larger than 25 MB.`, 413);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function json(url: string) {
  const res = await fetch(url, { headers: headers(), signal: AbortSignal.timeout(20_000) });
  if (res.status === 403 || res.status === 429) throw fail("GitHub's rate limit for anonymous requests was reached. Try again later, or set GITHUB_TOKEN on the server.", 429);
  return res;
}

export async function githubFile(url: string): Promise<RepoFile> {
  try {
    return await githubFileViaApi(url);
  } catch (e: any) {
    // Shared hosting IPs use up GitHub's anonymous API limit (60 an hour) quickly. raw.githubusercontent.com isn't
    // part of that limit, so look for the standard file names at the root (or in the linked folder) directly.
    if (e?.statusCode !== 429) throw e;
    return githubFileViaRaw(url);
  }
}

export async function githubFileViaRaw(url: string): Promise<RepoFile> {
  const { owner, repo, ref, path } = parseRepoUrl(url);
  const branch = ref ?? "HEAD"; // raw.githubusercontent.com resolves HEAD to the default branch
  const isFile = !!path && (LOCKFILES.includes(path.split("/").pop()!) || MCP_CONFIGS.some((c) => path === c || path.endsWith(`/${c}`)));
  const dir = isFile ? "" : (path ?? "").replace(/\/$/, "");
  const list = isFile ? [path!] : [...LOCKFILES, ...MCP_CONFIGS].map((n) => (dir ? `${dir}/${n}` : n));
  try {
    return await pickFrom(owner, repo, branch, list, null); // only names were tried, so nothing else is known to exist
  } catch (e: any) {
    if (e?.statusCode === 413) throw e;
    throw fail(
      `No lockfile or MCP config at ${dir ? `${owner}/${repo}/${dir}` : `the root of ${owner}/${repo}`}. GitHub's API limit was reached, so subfolders weren't searched: link to the folder instead, like https://github.com/${owner}/${repo}/tree/main/apps/web.`,
      404,
    );
  }
}

/** Download candidates in order and return the first one that parses into registry packages. */
async function pickFrom(owner: string, repo: string, branch: string, list: string[], others: string[] | null): Promise<RepoFile> {
  const tried: string[] = [];
  let found = 0;
  for (const p of list) {
    const res = await fetch(`https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(branch)}/${p.split("/").map(encodeURIComponent).join("/")}`, {
      signal: AbortSignal.timeout(30_000),
    });
    if (!res.ok) {
      await res.body?.cancel();
      continue;
    }
    found++;
    const content = await capped(res, `${p} in ${owner}/${repo}`);
    const filename = p.split("/").pop()!;
    try {
      const parsed = parseInput(filename, content); // e.g. a requirements.txt with no pinned versions: try the next file
      if (!parsed.packages.size && !parsed.mcp.length) throw new Error("no registry packages");
    } catch {
      tried.push(p);
      continue;
    }
    const dir = p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "";
    return { filename, content, name: dir ? `${owner}/${repo}/${dir}` : `${owner}/${repo}`, path: p, others: (others ?? []).filter((x) => x !== p).slice(0, 10) };
  }
  if (!found) throw fail(`None of ${list.slice(0, 3).join(", ")} exists in ${owner}/${repo}.`, 404);
  throw fail(`Found ${tried.join(", ")} in ${owner}/${repo}, but none has pinned versions Taintgraph can read. Commit a lockfile, or pin requirements with ==.`);
}

async function githubFileViaApi(url: string): Promise<RepoFile> {
  const { owner, repo, ref } = parseRepoUrl(url);
  let { path } = parseRepoUrl(url);
  const meta = await json(`https://api.github.com/repos/${owner}/${repo}`);
  if (!meta.ok) throw fail(`GitHub returned ${meta.status} for ${owner}/${repo}. Is the repository public?`, 404);
  let branch: string = ref ?? ((await meta.json()) as any).default_branch ?? "main";

  // A branch name can contain slashes (/tree/feature/x/apps/web): try longer branch names until GitHub knows one.
  let tree = await json(`https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`);
  const segments = path ? path.split("/") : [];
  while (!tree.ok && ref && segments.length) {
    branch = `${branch}/${segments.shift()}`;
    path = segments.join("/") || undefined;
    tree = await json(`https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`);
  }
  if (!tree.ok) throw fail(`GitHub returned ${tree.status} for the ${branch} branch of ${owner}/${repo}.`, 404);
  const all = (((await tree.json()) as any).tree ?? []).filter((e: any) => e.type === "blob").map((e: any) => e.path as string);
  // A link straight to a file scans that file; a link to a folder looks inside it.
  let list = path && all.includes(path) ? [path] : candidates(all, path);
  // A workspace package (apps/web) usually has no lockfile of its own: use the nearest one above it, like the package manager does.
  if (!list.length && path) list = parentLockfiles(all, path);
  if (!list.length)
    throw fail(`No lockfile or MCP config in ${owner}/${repo}${path ? `/${path}` : ""}. Supported: ${LOCKFILES.join(", ")}, and MCP configs (${MCP_CONFIGS.join(", ")}).`);

  return pickFrom(owner, repo, branch, list.slice(0, 6), list);
}
