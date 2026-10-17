import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { DependencyGraph, FindingStatus, ProjectSummary } from "@api/types";
import { api, findingGroup, formatWhen, isoTime, prefersReducedMotion, toApiError, VERDICT_LABEL } from "../api";
import { href } from "../App";
import Graph from "./Graph";
import Findings, { type FocusRequest } from "./Findings";
import Accounts, { type SimState } from "./Accounts";
import Markdown from "./Markdown";
import FixPlan from "./FixPlan";
import Changes from "./Changes";
import { ErrorState, Loading } from "./States";

function ReportDialog({ id, open, onClose }: { id: string; open: boolean; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  const [md, setMd] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [copied, setCopied] = useState("");

  const load = useCallback(() => {
    setError(null);
    setMd(null);
    api.report(id).then((r) => setMd(r.markdown), setError);
  }, [id]);

  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) {
      d.showModal();
      if (md === null) load();
    } else if (!open && d.open) d.close();
  }, [open, load, md]);

  const copy = async () => {
    if (!md) return;
    try {
      await navigator.clipboard.writeText(md);
      setCopied("Copied");
    } catch {
      const ta = document.createElement("textarea");
      ta.value = md;
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand("copy");
        setCopied("Copied");
      } catch {
        setCopied("Couldn't copy. Select the text and copy it yourself.");
      }
      ta.remove();
    }
    window.setTimeout(() => setCopied(""), 2500);
  };

  return (
    <dialog ref={ref} className="report-dialog" aria-labelledby="report-h" onClose={onClose}>
      <div className="dialog-head">
        <h2 id="report-h">Report</h2>
        <div className="dialog-actions">
          <button type="button" className="btn btn-small" onClick={copy} disabled={!md}>
            Copy
          </button>
          <span role="status" className="copied">
            {copied}
          </span>
          <button type="button" className="btn btn-small" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
      <div className="dialog-body">
        {error ? <ErrorState error={error} onRetry={load} /> : md === null ? <Loading label="Writing the report" /> : <Markdown source={md} headingBase={3} />}
      </div>
    </dialog>
  );
}

export default function Project({ id }: { id: string }) {
  const [summary, setSummary] = useState<ProjectSummary | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [graph, setGraph] = useState<DependencyGraph | null>(null);
  const [graphError, setGraphError] = useState<unknown>(null);
  const [focusReq, setFocusReq] = useState<FocusRequest | null>(null);
  const [highlightNode, setHighlightNode] = useState<string | null>(null);
  const [reportOpen, setReportOpen] = useState(false);
  const [sim, setSim] = useState<SimState>({ status: "idle" });
  const timers = useRef<number[]>([]);

  const load = useCallback(() => {
    const ctrl = new AbortController();
    setError(null);
    setGraphError(null);
    api.project(id, ctrl.signal).then(setSummary, (e) => !ctrl.signal.aborted && setError(e));
    api.graph(id, ctrl.signal).then(setGraph, (e) => !ctrl.signal.aborted && setGraphError(e));
    return ctrl;
  }, [id]);

  useEffect(() => {
    const ctrl = load();
    return () => {
      ctrl.abort();
      timers.current.forEach((t) => window.clearTimeout(t));
    };
  }, [load]);

  useEffect(() => {
    document.title = summary ? `${summary.name} · Taintgraph` : "Project · Taintgraph";
  }, [summary]);

  const counts = useMemo(() => {
    const live = (summary?.findings ?? []).filter((f) => f.status === "open" || f.status === "confirmed");
    return {
      malware: live.filter((f) => findingGroup(f) === "compromise").length,
      suspicious: live.filter((f) => findingGroup(f) === "suspicious").length,
      vulnerable: live.filter((f) => findingGroup(f) === "vulnerability").length,
      decided: (summary?.findings ?? []).filter((f) => f.status === "confirmed" || f.status === "dismissed" || f.status === "accepted").length,
    };
  }, [summary]);

  const onStatusChange = useCallback((fid: string, status: FindingStatus, note: string) => {
    setSummary((s) =>
      s ? { ...s, findings: s.findings.map((f) => (f.id === fid ? { ...f, status, statusNote: note || f.statusNote } : f)) } : s,
    );
  }, []);

  const select = useCallback((versionKey: string) => {
    setHighlightNode(versionKey);
    setFocusReq({ versionKey, nonce: Date.now() });
  }, []);

  const skipGraph = useCallback(() => {
    const h = document.getElementById("findings-h");
    h?.focus();
    h?.scrollIntoView({ block: "start" });
  }, []);

  const simulate = useCallback(
    async (login: string) => {
      timers.current.forEach((t) => window.clearTimeout(t));
      timers.current = [];
      setSim({ status: "loading", login });
      try {
        const result = await api.simulate(id, login, 4);
        const waves = result.waves.length;
        if (waves === 0 || prefersReducedMotion()) {
          setSim({ status: "done", login, result, wave: Math.max(0, ...result.waves.map((w) => w.wave)) });
          return;
        }
        const ordered = [...result.waves].sort((a, b) => a.wave - b.wave);
        setSim({ status: waves === 1 ? "done" : "running", login, result, wave: ordered[0].wave });
        ordered.slice(1).forEach((w, i) => {
          const t = window.setTimeout(() => {
            setSim({ status: i === ordered.length - 2 ? "done" : "running", login, result, wave: w.wave });
          }, (i + 1) * 1000);
          timers.current.push(t);
        });
      } catch (e) {
        setSim({ status: "error", login, error: toApiError(e) });
      }
    },
    [id],
  );

  const { poisoned, poisonedAll } = useMemo(() => {
    const p = new Set<string>();
    const all = new Set<string>();
    if (sim.status === "running" || sim.status === "done") {
      for (const w of sim.result.waves) {
        for (const k of w.poisoned) {
          all.add(k);
          if (w.wave <= sim.wave) p.add(k);
        }
      }
    }
    return { poisoned: p, poisonedAll: all };
  }, [sim]);

  if (error) {
    return (
      <div className="page narrow">
        <h1 id="page-title" tabIndex={-1}>
          {toApiError(error).kind === "not_found" ? "Project not found" : "Couldn't load this project"}
        </h1>
        <ErrorState error={error} onRetry={() => load()} />
        <p>
          <a href={href.intake()}>Back to Scan</a>
        </p>
      </div>
    );
  }

  if (!summary) {
    return (
      <div className="page">
        <h1 id="page-title" tabIndex={-1} className="loading-title">
          Loading project
        </h1>
        <Loading label="Reading the graph for this project" />
      </div>
    );
  }

  const v = summary.verdict;
  return (
    <div className="page project">
      <header className="project-head">
        <div>
          <h1 id="page-title" tabIndex={-1}>
            {summary.name}
          </h1>
          <p className="subtitle">
            {summary.source} · scanned <time dateTime={isoTime(summary.scannedAt)}>{formatWhen(summary.scannedAt)}</time> ·{" "}
            {summary.counts.packages} packages, {summary.counts.direct} direct
          </p>
        </div>
        <div className="head-actions">
          <a className="btn btn-primary" href={href.ask(summary.id)}>
            Ask Taintgraph
          </a>
          <button type="button" className="btn" onClick={() => setReportOpen(true)}>
            Report
          </button>
        </div>
      </header>

      <section className={`verdict verdict-${v}`} aria-labelledby="verdict-h">
        <div className="verdict-main">
          <h2 id="verdict-h" className="verdict-word">
            {VERDICT_LABEL[v] ?? v}
          </h2>
          <ul className="verdict-counts">
            <li>
              <strong>{counts.malware}</strong> malware
            </li>
            <li>
              <strong>{counts.suspicious}</strong> suspicious
            </li>
            <li>
              <strong>{counts.vulnerable}</strong> vulnerable
            </li>
            {counts.decided > 0 && <li className="decided">{counts.decided} decided</li>}
          </ul>
          <p className="verdict-reach">
            <strong>{summary.counts.accounts}</strong> {summary.counts.accounts === 1 ? "account can" : "accounts can"} publish code in this
            project.
          </p>
        </div>
        <details className="explain">
          <summary>What am I looking at?</summary>
          <div className="explain-body">
            <p>
              Taintgraph loaded every package version in your lockfile into a graph, with who can publish each package and every
              advisory that names it.
            </p>
            <ul>
              <li>
                <strong>Compromised</strong> means a version you install is listed in a malware advisory or was pulled from the
                registry.
              </li>
              <li>
                <strong>Suspicious</strong> means a release looks like an account takeover, typosquat or risky install script, but
                nothing has confirmed it yet.
              </li>
              <li>
                <strong>Vulnerable</strong> counts ordinary security bugs (CVEs). They matter, but they aren't an attack in progress.
              </li>
            </ul>
            <p>
              Counts include findings that are open or that you marked as a real threat. Your verdicts teach Taintgraph rules for the
              next scan.
            </p>
          </div>
        </details>
      </section>

      <Changes projectId={summary.id} scanId={summary.scanId} />

      <section className="graph-section" aria-labelledby="graph-h">
        <h2 id="graph-h">Dependency graph</h2>
        <p className="muted">Dependencies drain into your app on the right; red paths carry something dangerous.</p>
        {graphError ? (
          <ErrorState error={graphError} onRetry={() => load()} title="The graph didn't load." />
        ) : !graph ? (
          <Loading label="Drawing the dependency graph" />
        ) : graph.nodes.length <= 1 ? (
          <p className="muted">This project has no dependencies to draw.</p>
        ) : (
          <Graph graph={graph} poisoned={poisoned} poisonedAll={poisonedAll} highlight={highlightNode} onSelect={select} skipTo={skipGraph} />
        )}
      </section>

      <section className="fix-section" aria-labelledby="fix-h">
        <h2 id="fix-h">How to fix it</h2>
        <FixPlan projectId={summary.id} refreshKey={summary.findings.map((f) => f.status[0]).join("")} />
      </section>

      <div className="columns">
        <section className="col-findings" aria-labelledby="findings-h">
          <h2 id="findings-h" tabIndex={-1}>
            Findings
          </h2>
          <Findings findings={summary.findings} projectName={summary.name} focusRequest={focusReq} onStatusChange={onStatusChange} />
        </section>
        <aside className="col-accounts" aria-labelledby="accounts-h">
          <h2 id="accounts-h">Who can publish your code</h2>
          <Accounts
            projectId={summary.id}
            top={summary.topAccounts}
            total={summary.counts.accounts}
            sim={sim}
            onSimulate={simulate}
            onReset={() => {
              timers.current.forEach((t) => window.clearTimeout(t));
              setSim({ status: "idle" });
            }}
          />
          {summary.mcpServers.length > 0 && (
            <section className="mcp" aria-labelledby="mcp-h">
              <h2 id="mcp-h">MCP servers</h2>
              <ul className="mcp-list">
                {summary.mcpServers.map((m) => (
                  <li key={`${m.client}-${m.name}`}>
                    <div className="mcp-top">
                      <strong>{m.name}</strong>
                      <span className="muted small">{m.client}</span>
                      <span className={m.pinned ? "pill pill-clean" : "pill pill-suspicious"}>{m.pinned ? "Pinned" : "Unpinned"}</span>
                    </div>
                    <code className="cmd">{m.command}</code>
                    {m.advisories.length > 0 && (
                      <p className="mcp-adv">
                        <span className="taint-text">Advisories:</span>{" "}
                        {m.advisories.map((a, i) => (
                          <span key={a}>
                            {i > 0 && ", "}
                            <code>{a}</code>
                          </span>
                        ))}
                      </p>
                    )}
                    {!m.pinned && (
                      <p className="muted small">
                        Runs whatever version the registry serves at launch. Pin a version so a hijacked release can't reach you.
                      </p>
                    )}
                  </li>
                ))}
              </ul>
            </section>
          )}
        </aside>
      </div>

      <ReportDialog id={summary.id} open={reportOpen} onClose={() => setReportOpen(false)} />
    </div>
  );
}
