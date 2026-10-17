// API contract shared by the server and the web app. The web app imports these types directly.

export type Ecosystem = "npm" | "PyPI";
export type Severity = "critical" | "high" | "medium" | "low";

export type SignalId =
  | "malware" // a MAL- advisory explicitly lists this version
  | "possible_malware" // a malware advisory matches only through a version range
  | "removed" // the registry no longer serves this version (npm/PyPI delete malware releases) or npm's -security placeholder
  | "takeover" // publisher changed and an install script appeared
  | "risky_install_script" // install hook pipes downloads to a shell, decodes base64, touches credentials...
  | "typosquat" // one edit from a top package, with a tiny fraction of its downloads
  | "provenance_dropped" // previous release had a build attestation, this one doesn't
  | "new_install_script"
  | "unpinned_mcp" // MCP server started with npx/uvx and no version
  | "fresh_release" // published less than 72 hours before the scan
  | "vulnerability"; // ordinary CVE/GHSA advisory

/** Compromise signals: memory and learned rules may never skip these automatically. */
export const COMPROMISE: SignalId[] = ["malware", "possible_malware", "removed"];

export type FindingStatus = "open" | "confirmed" | "dismissed" | "accepted" | "skipped";
// confirmed = "Real threat", dismissed = "Not a threat", accepted = "Risk accepted", skipped = by memory or a rule

export interface Evidence {
  nodes: string[]; // node keys, e.g. "project/abc", "npm/chalk@5.6.1", "npm-user/qix"
  edges: [string, string, string][]; // [from, to, relationship]
}

export interface AdvisoryRef {
  id: string;
  summary: string;
  url: string;
}

export interface FindingView {
  id: string;
  versionKey: string;
  name: string;
  version: string;
  ecosystem: Ecosystem;
  signal: SignalId;
  severity: Severity;
  title: string;
  detail: string;
  path: string[]; // route from the project root to the version
  advisories: AdvisoryRef[];
  status: FindingStatus;
  statusNote?: string;
  fix?: string;
}

export interface AccountView {
  key: string; // "npm-user/qix", "pypi-user/x", "pypi-org/y", "workflow/npm:pkg"
  login: string;
  kind: "user" | "org" | "workflow";
  versions: number;
  share: number; // of the project's versions (0..1)
  weight: number; // sum of PageRank of those versions
  flagged: boolean; // maintains or published a flagged version
}

export interface McpServerView {
  name: string;
  client: string;
  command: string;
  pinned: boolean;
  packageKey: string | null;
  advisories: string[];
}

export interface ProjectSummary {
  id: string;
  name: string;
  kind: "app" | "agent-config";
  source: string; // lockfile type, e.g. "package-lock v3", "uv.lock v1", "MCP config (Claude Code)"
  scanId: string;
  scannedAt: number;
  counts: { packages: number; direct: number; accounts: number; advisories: number; edges: number };
  verdict: "compromised" | "suspicious" | "vulnerable" | "clean"; // suspicious = tampering signals; vulnerable = known high/critical CVEs only
  findings: FindingView[];
  topAccounts: AccountView[];
  mcpServers: McpServerView[];
}

export interface ProjectListItem {
  id: string;
  name: string;
  kind: ProjectSummary["kind"];
  source: string;
  scannedAt: number;
  verdict: ProjectSummary["verdict"];
}

export interface GraphNode {
  key: string;
  name: string;
  version: string;
  depth: number; // hops from the project (project = 0)
  risk: "malware" | "suspicious" | "vuln" | null;
  direct: boolean;
  dev: boolean;
}

export interface DependencyGraph {
  root: string; // "project/<id>"
  rootName: string;
  nodes: GraphNode[]; // includes the root
  edges: { from: string; to: string }[]; // tree edges, dependency -> dependent (toward the root)
  infected: { from: string; to: string }[]; // edges on a route from a compromised/suspicious version to the root
}

export interface WormWave {
  wave: number;
  accounts: string[]; // logins compromised in this wave
  poisoned: string[]; // version keys newly poisoned in this wave
}

export interface WormResult {
  start: string;
  waves: WormWave[];
  poisonedShare: number;
  compromisedAccounts: number;
  totalVersions: number;
}

/** Typed answer outcomes (after the event guide): the UI shows which kind of answer it is. */
export type Outcome = "answered" | "from_memory" | "not_in_graph" | "unknown_name";

export interface StepView {
  index: number; // 1-based
  tool: string;
  label: string; // plain-language label, e.g. "Traced exposures"
  input: Record<string, unknown>;
  outcome: Outcome;
  summary: string;
  cypher: string;
  evidence: Evidence;
  at: number;
}

export interface InvestigationView {
  id: string;
  projectId: string;
  question: string;
  status: "running" | "done" | "error";
  agent: string; // "built-in" or "<model> via <provider>"
  answer?: string;
  outcome?: Outcome;
  validated?: boolean; // every name in the answer was found in the tool results
  startedAt: number;
  steps: StepView[];
  evidence: Evidence;
  followsId?: string; // the investigation this one follows up on, in the same conversation
}

export interface RuleView {
  id: string;
  when: SignalId;
  then: "escalate" | "skip";
  status: "proposed" | "active";
  confidence: number;
  learnedFrom: string[];
}

export interface TaskView {
  id: string;
  type: "analyze" | "report";
  forAgent: "analyst" | "reporter";
  status: "open" | "claimed" | "done" | "error";
  claimedBy?: string;
  createdAt: number;
  doneAt?: number;
  projectName: string;
}

export interface MemoryView {
  investigations: { id: string; question: string; projectId: string; projectName: string; startedAt: number; agent: string }[];
  verdicts: { findingId: string; versionKey: string; signal: SignalId; verdict: FindingStatus; note: string; at: number }[];
  rules: RuleView[];
  tasks: TaskView[];
}

export interface Sample {
  id: string;
  title: string;
  description: string;
  filename: string;
}

export type ScanEvent =
  | { type: "progress"; stage: string; message: string; pct: number }
  | { type: "done"; projectId: string }
  | { type: "error"; message: string };

/** What changed between a project's two latest scans. */
export interface ScanChanges {
  since: number | null; // when the previous scan ran; null when there is only one scan
  added: { name: string; version: string }[]; // packages that weren't installed before
  removed: { name: string; version: string }[];
  changed: { name: string; from: string[]; to: string[] }[]; // same package, different versions
  newlyFlagged: { findingId: string; versionKey: string; name: string; version: string; signal: SignalId; severity: Severity; title: string }[]; // open findings on versions the previous scan didn't have
}

/** One change in a fix plan: move a flagged version to a safe one (or remove it). */
export interface FixItem {
  name: string;
  ecosystem: Ecosystem;
  from: string;
  to: string | null; // null: no safe version known yet
  action: "upgrade" | "pin_previous" | "remove" | "no_fix"; // no_fix: a vulnerability with no fixed release yet; keep watching
  why: SignalId;
  severity: Severity;
  findingIds: string[];
  direct: boolean; // declared by the project itself, so edit the manifest; otherwise override the transitive version
  dev: boolean;
  majorChange: boolean; // the target is on a different major version: check for breaking changes
  check: "clean" | "has_vulnerabilities" | "unchecked"; // the target re-checked against OSV.dev
  note: string;
}

export interface FixPlan {
  projectId: string;
  items: FixItem[];
  npm: { overrides: Record<string, string>; pnpmOverrides: Record<string, string>; resolutions: Record<string, string>; commands: string[] } | null;
  python: { commands: string[]; constraints: string } | null;
  incident: string[]; // steps for compromised versions: what to rotate and check
  skipped: number; // lower-severity findings left out of the plan
}

/** Result of a Sentinel retro-hunt: new advisories for versions some project already installed. */
export interface SentinelResult {
  checked: number; // versions re-checked against OSV.dev
  newAdvisories: number;
  hits: { projectId: string; projectName: string; versionKey: string; advisoryId: string }[];
}

export type InvestigateEvent =
  | { type: "started"; investigationId: string; agent: string }
  | { type: "step"; step: StepView }
  | { type: "answer"; text: string; outcome: Outcome; validated: boolean }
  | { type: "done"; investigationId: string }
  | { type: "error"; message: string };

/*
REST API. JSON everywhere. Workspace from header `x-taintgraph-org` (default "demo"; [A-Za-z0-9_-]{1,64}).
GET  /api/health                              -> { ok, falkordb, llm, agent }
GET  /api/samples                             -> Sample[]
POST /api/scan  { sample } | { filename, content } | { githubUrl }   -> text/event-stream of ScanEvent
GET  /api/projects                            -> ProjectListItem[]
GET  /api/projects/:id                        -> ProjectSummary
GET  /api/projects/:id/graph                  -> DependencyGraph
GET  /api/projects/:id/accounts               -> AccountView[] (top 25)
POST /api/projects/:id/simulate { login, waves? }   -> WormResult
POST /api/projects/:id/ask { question, followUp? }  -> text/event-stream of InvestigateEvent (followUp: an investigation id to continue)
GET  /api/projects/:id/report                 -> { markdown }
GET  /api/projects/:id/fix                    -> FixPlan
GET  /api/projects/:id/changes                -> ScanChanges
GET  /api/investigations/:id                  -> InvestigationView
POST /api/findings/:id/verdict { verdict: "confirmed" | "dismissed" | "accepted", note? } -> { ok, proposedRule?: RuleView }
GET  /api/memory                              -> MemoryView
POST /api/rules/:id/activate                  -> { ok }
POST /api/sentinel                            -> SentinelResult
Errors: { error: string } with 4xx/5xx. 429 when rate limited.
*/
