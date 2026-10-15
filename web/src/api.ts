import type {
  AccountView,
  DependencyGraph,
  FindingStatus,
  FindingView,
  InvestigateEvent,
  InvestigationView,
  MemoryView,
  Outcome,
  ProjectListItem,
  ProjectSummary,
  RuleView,
  Sample,
  ScanEvent,
  Severity,
  SignalId,
  WormResult,
} from "@api/types";

/* ---------- workspace (org) ---------- */

const ORG_KEY = "upstream-org";
const ORG_RE = /^[A-Za-z0-9_-]{1,64}$/;

export function getOrg(): string {
  try {
    const v = window.localStorage.getItem(ORG_KEY);
    if (v && ORG_RE.test(v)) return v;
  } catch {
    /* storage blocked */
  }
  return "demo";
}

export function setOrg(org: string): void {
  try {
    if (ORG_RE.test(org)) window.localStorage.setItem(ORG_KEY, org);
  } catch {
    /* storage blocked */
  }
}

/* ---------- errors ---------- */

export type ErrorKind = "unreachable" | "rate_limited" | "not_found" | "bad_request" | "server";

export class ApiError extends Error {
  kind: ErrorKind;
  status: number;
  constructor(kind: ErrorKind, message: string, status = 0) {
    super(message);
    this.kind = kind;
    this.status = status;
  }
}

export const SERVER_DOWN = "Upstream's server isn't responding. Try again in a moment.";
export const RATE_LIMITED = "Upstream is handling a lot of requests right now. Wait a minute, then try again.";

function friendly(status: number, serverMessage: string | undefined): ApiError {
  if (status === 429) return new ApiError("rate_limited", RATE_LIMITED, status);
  if (status === 404) return new ApiError("not_found", serverMessage || "We couldn't find that.", status);
  if (status === 502 || status === 503 || status === 504) return new ApiError("unreachable", SERVER_DOWN, status);
  if (status >= 500) {
    if (!serverMessage) return new ApiError("unreachable", SERVER_DOWN, status);
    return new ApiError("server", cleanMessage(serverMessage), status);
  }
  return new ApiError("bad_request", cleanMessage(serverMessage || "That request didn't work."), status);
}

/** Strip transport jargon ("HTTP 429", "status 429", "Too Many Requests") from messages shown to people. */
export function cleanMessage(msg: string): string {
  if (/\b429\b|too many requests|rate.?limit/i.test(msg)) return RATE_LIMITED;
  if (/ECONNREFUSED|fetch failed|Failed to fetch|NetworkError|Load failed/i.test(msg)) return SERVER_DOWN;
  return msg.replace(/\bHTTP\s*\d{3}:?\s*/gi, "").trim() || "Something went wrong.";
}

export function toApiError(e: unknown): ApiError {
  if (e instanceof ApiError) return e;
  if (e instanceof DOMException && e.name === "AbortError") return new ApiError("server", "Cancelled.");
  if (e instanceof TypeError) return new ApiError("unreachable", SERVER_DOWN);
  if (e instanceof Error) return new ApiError("server", cleanMessage(e.message));
  return new ApiError("server", "Something went wrong.");
}

/* ---------- fetch helpers ---------- */

function headers(json: boolean): HeadersInit {
  const h: Record<string, string> = { "x-upstream-org": getOrg(), accept: "application/json" };
  if (json) h["content-type"] = "application/json";
  return h;
}

async function readError(res: Response): Promise<ApiError> {
  let msg: string | undefined;
  try {
    const text = await res.text();
    try {
      const body = JSON.parse(text) as { error?: unknown; message?: unknown };
      if (typeof body.error === "string") msg = body.error;
      else if (typeof body.message === "string") msg = body.message;
    } catch {
      /* not JSON: likely a proxy error page */
    }
  } catch {
    /* ignore */
  }
  return friendly(res.status, msg);
}

async function request<T>(method: "GET" | "POST", path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, {
      method,
      headers: headers(body !== undefined),
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal,
    });
  } catch (e) {
    throw toApiError(e);
  }
  if (!res.ok) throw await readError(res);
  try {
    return (await res.json()) as T;
  } catch {
    throw new ApiError("unreachable", SERVER_DOWN, res.status);
  }
}

export const getJSON = <T>(path: string, signal?: AbortSignal) => request<T>("GET", path, undefined, signal);
export const postJSON = <T>(path: string, body: unknown, signal?: AbortSignal) => request<T>("POST", path, body, signal);

/** POST that answers with text/event-stream. Calls onEvent for each `data: {json}` frame. */
export async function streamSSE<E>(path: string, body: unknown, onEvent: (e: E) => void, signal?: AbortSignal): Promise<void> {
  let res: Response;
  try {
    res = await fetch(path, {
      method: "POST",
      headers: { ...headers(true), accept: "text/event-stream" },
      body: JSON.stringify(body),
      signal,
    });
  } catch (e) {
    throw toApiError(e);
  }
  if (!res.ok) throw await readError(res);
  if (!res.body) throw new ApiError("unreachable", SERVER_DOWN, res.status);

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  const flush = (frame: string) => {
    const data = frame
      .split(/\r?\n/)
      .filter((l) => l.startsWith("data:"))
      .map((l) => l.slice(5).replace(/^ /, ""))
      .join("\n");
    if (!data) return;
    try {
      onEvent(JSON.parse(data) as E);
    } catch {
      /* ignore malformed frame */
    }
  };
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let idx: number;
      while ((idx = buffer.search(/\r?\n\r?\n/)) !== -1) {
        const frame = buffer.slice(0, idx);
        const m = buffer.slice(idx).match(/^\r?\n\r?\n/);
        buffer = buffer.slice(idx + (m ? m[0].length : 2));
        flush(frame);
      }
    }
    buffer += decoder.decode();
    if (buffer.trim()) flush(buffer);
  } catch (e) {
    throw toApiError(e);
  }
}

/* ---------- endpoints ---------- */

export type ScanRequest = { sample: string } | { filename: string; content: string } | { githubUrl: string };
export type Verdict = "confirmed" | "dismissed" | "accepted";

const enc = encodeURIComponent;

export const api = {
  samples: () => getJSON<Sample[]>("/api/samples"),
  projects: () => getJSON<ProjectListItem[]>("/api/projects"),
  project: (id: string, s?: AbortSignal) => getJSON<ProjectSummary>(`/api/projects/${enc(id)}`, s),
  graph: (id: string, s?: AbortSignal) => getJSON<DependencyGraph>(`/api/projects/${enc(id)}/graph`, s),
  accounts: (id: string) => getJSON<AccountView[]>(`/api/projects/${enc(id)}/accounts`),
  simulate: (id: string, login: string, waves = 4) => postJSON<WormResult>(`/api/projects/${enc(id)}/simulate`, { login, waves }),
  report: (id: string) => getJSON<{ markdown: string }>(`/api/projects/${enc(id)}/report`),
  investigation: (id: string, s?: AbortSignal) => getJSON<InvestigationView>(`/api/investigations/${enc(id)}`, s),
  verdict: (findingId: string, verdict: Verdict, note?: string) =>
    postJSON<{ ok: boolean; proposedRule?: RuleView }>(`/api/findings/${enc(findingId)}/verdict`, note ? { verdict, note } : { verdict }),
  memory: () => getJSON<MemoryView>("/api/memory"),
  activateRule: (ruleId: string) => postJSON<{ ok: boolean }>(`/api/rules/${enc(ruleId)}/activate`, {}),
  scan: (req: ScanRequest, onEvent: (e: ScanEvent) => void, signal?: AbortSignal) => streamSSE<ScanEvent>("/api/scan", req, onEvent, signal),
  ask: (id: string, question: string, onEvent: (e: InvestigateEvent) => void, signal?: AbortSignal) =>
    streamSSE<InvestigateEvent>(`/api/projects/${enc(id)}/ask`, { question }, onEvent, signal),
};

/* ---------- labels and helpers ---------- */

export const COMPROMISE_SIGNALS: SignalId[] = ["malware", "possible_malware", "removed"];

export const SIGNAL_LABEL: Record<SignalId, string> = {
  malware: "Malware advisory",
  possible_malware: "Possible malware",
  removed: "Removed from the registry",
  takeover: "Possible account takeover",
  risky_install_script: "Risky install script",
  typosquat: "Possible typosquat",
  provenance_dropped: "Provenance dropped",
  new_install_script: "New install script",
  unpinned_mcp: "Unpinned MCP server",
  fresh_release: "Fresh release",
  vulnerability: "Vulnerability",
};

export const signalLabel = (s: SignalId | string) => SIGNAL_LABEL[s as SignalId] ?? s;

export const STATUS_LABEL: Record<FindingStatus, string> = {
  open: "Needs review",
  confirmed: "Real threat",
  dismissed: "Not a threat",
  accepted: "Risk accepted",
  skipped: "Skipped",
};

export const OUTCOME_LABEL: Record<Outcome, string> = {
  answered: "Answered with a path",
  from_memory: "Answered from memory",
  not_in_graph: "Not in the graph",
  unknown_name: "Unknown name",
};

export const KIND_LABEL: Record<AccountView["kind"], string> = {
  user: "User account",
  org: "Organization",
  workflow: "CI workflow",
};

export const VERDICT_LABEL: Record<ProjectSummary["verdict"], string> = {
  compromised: "Compromised",
  suspicious: "Suspicious",
  clean: "Clean",
};

export const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export const severityLabel = (s: Severity) => s.charAt(0).toUpperCase() + s.slice(1);

/** Finding kind used for grouping. */
export function findingGroup(f: FindingView): "compromise" | "suspicious" | "vulnerability" {
  if (COMPROMISE_SIGNALS.includes(f.signal)) return "compromise";
  if (f.signal === "vulnerability") return "vulnerability";
  return "suspicious";
}

export function compareFindings(a: FindingView, b: FindingView): number {
  const g = { compromise: 0, suspicious: 1, vulnerability: 2 };
  return g[findingGroup(a)] - g[findingGroup(b)] || SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || a.name.localeCompare(b.name);
}

/** "npm/chalk@5.6.1" -> "chalk@5.6.1", "pypi/requests@2" -> "requests@2", "npm-user/qix" -> "qix". */
export function shortKey(key: string, projectName?: string): string {
  if (key.startsWith("project/")) return projectName ?? key.slice("project/".length);
  const m = key.match(/^(npm|pypi|PyPI|npm-user|pypi-user|pypi-org|workflow|advisory|mcp)\/(.*)$/);
  return m ? m[2] : key;
}

export function nodeKind(key: string): "project" | "package" | "account" | "advisory" | "other" {
  if (key.startsWith("project/")) return "project";
  if (/^(npm|pypi|PyPI)\//.test(key)) return "package";
  if (/^(npm-user|pypi-user|pypi-org|workflow)\//.test(key)) return "account";
  if (key.startsWith("advisory/") || /^(MAL|GHSA|CVE|PYSEC)-/.test(key)) return "advisory";
  return "other";
}

export function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, Math.max(1, max - 1)) + "…" : s;
}

const toMs = (t: number) => (t < 1e12 ? t * 1000 : t);

export function formatWhen(t: number): string {
  if (!t || !Number.isFinite(t)) return "unknown time";
  const ms = toMs(t);
  const diff = Date.now() - ms;
  if (diff >= 0 && diff < 60_000) return "just now";
  if (diff >= 0 && diff < 3_600_000) return `${Math.round(diff / 60_000)} min ago`;
  if (diff >= 0 && diff < 86_400_000) return `${Math.round(diff / 3_600_000)} h ago`;
  return new Date(ms).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function isoTime(t: number): string {
  try {
    return new Date(toMs(t)).toISOString();
  } catch {
    return "";
  }
}

export const pct = (share: number) => `${Math.round(share * 100)}%`;

export function prefersReducedMotion(): boolean {
  try {
    return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  } catch {
    return false;
  }
}

/* ---------- session storage (scroll restore) ---------- */

export function sessionGet(key: string): string | null {
  try {
    return window.sessionStorage.getItem(key);
  } catch {
    return null;
  }
}

export function sessionSet(key: string, value: string): void {
  try {
    window.sessionStorage.setItem(key, value);
  } catch {
    /* ignore */
  }
}
