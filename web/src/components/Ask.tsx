import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Evidence, InvestigateEvent, Outcome, ProjectSummary, StepView } from "@api/types";
import { api, cleanMessage, compareFindings, findingGroup, OUTCOME_LABEL, toApiError } from "../api";
import { href } from "../App";
import EvidenceGraph, { mergeEvidence, type FlagMap } from "./EvidenceGraph";
import Markdown from "./Markdown";
import { ErrorState, Loading } from "./States";

interface Turn {
  key: string;
  question: string;
  investigationId?: string;
  agent?: string;
  steps: StepView[];
  answer?: string;
  outcome?: Outcome;
  validated?: boolean;
  evidence?: Evidence;
  status: "running" | "done" | "error";
  error?: string;
}

function agentLabel(agent?: string): string {
  if (!agent || agent === "built-in" || agent === "builtin") return "Taintgraph's built-in investigator";
  return `Answered by ${agent}`;
}

function OutcomePill({ outcome }: { outcome: Outcome }) {
  return <span className={`pill outcome-${outcome}`}>{OUTCOME_LABEL[outcome] ?? outcome}</span>;
}

function suggestions(s: ProjectSummary): string[] {
  const out: string[] = [];
  const flagged = [...s.findings].filter((f) => f.status !== "skipped").sort(compareFindings);
  const top = flagged.find((f) => findingGroup(f) !== "vulnerability") ?? flagged[0];
  if (top) out.push(`Why is ${top.name}@${top.version} flagged?`);
  out.push("Which accounts could poison our tree?");
  const acct = s.topAccounts[0];
  if (acct) out.push(`What if ${acct.login}'s account gets hacked?`);
  if (s.mcpServers.length > 0) out.push("Which MCP servers could run code we haven't reviewed?");
  out.push("Are we exposed to any malware?");
  return out;
}

function Steps({ turn }: { turn: Turn }) {
  const steps = [...turn.steps].sort((a, b) => a.index - b.index);
  if (!steps.length) {
    return turn.status === "running" ? <Loading label="Planning the first step" compact /> : <p className="muted small">No graph steps were recorded for this answer.</p>;
  }
  return (
    <ol className="steps">
      {steps.map((s) => (
        <li key={s.index} className="step">
          <span className="step-n" aria-hidden="true">
            {s.index}
          </span>
          <div className="step-body">
            <p className="step-title">
              <span className="visually-hidden">Step {s.index}: </span>
              <strong>{s.label}</strong> <code className="tool">{s.tool}</code> <OutcomePill outcome={s.outcome} />
            </p>
            {s.summary && <p className="step-summary">{s.summary}</p>}
            {s.cypher && (
              <details className="cypher">
                <summary>Cypher query</summary>
                <pre className="code-block">
                  <code>{s.cypher}</code>
                </pre>
              </details>
            )}
          </div>
        </li>
      ))}
    </ol>
  );
}

export default function Ask({ id, investigationId }: { id: string; investigationId?: string }) {
  const [summary, setSummary] = useState<ProjectSummary | null>(null);
  const [summaryError, setSummaryError] = useState<unknown>(null);
  const [turns, setTurns] = useState<Turn[]>([]);
  const [active, setActive] = useState<string | null>(null);
  const [question, setQuestion] = useState("");
  const [deepError, setDeepError] = useState<unknown>(null);
  const [announce, setAnnounce] = useState("");
  const abortRef = useRef<AbortController | null>(null);
  const logEnd = useRef<HTMLDivElement>(null);

  const loadSummary = useCallback(() => {
    setSummaryError(null);
    api.project(id).then(setSummary, setSummaryError);
  }, [id]);

  useEffect(() => {
    loadSummary();
    return () => abortRef.current?.abort();
  }, [loadSummary]);

  useEffect(() => {
    document.title = summary ? `Ask about ${summary.name} · Taintgraph` : "Ask · Taintgraph";
  }, [summary]);

  const loadDeep = useCallback(() => {
    if (!investigationId) return;
    setDeepError(null);
    api.investigation(investigationId).then(
      (inv) => {
        const t: Turn = {
          key: inv.id,
          question: inv.question,
          investigationId: inv.id,
          agent: inv.agent,
          steps: inv.steps,
          answer: inv.answer,
          outcome: inv.outcome,
          validated: inv.validated,
          evidence: inv.evidence,
          status: inv.status === "running" ? "running" : inv.status,
          error: inv.status === "error" ? "This investigation stopped before it finished." : undefined,
        };
        setTurns((ts) => [t, ...ts.filter((x) => x.key !== t.key)]);
        setActive(t.key);
      },
      setDeepError,
    );
  }, [investigationId]);

  useEffect(() => {
    loadDeep();
  }, [loadDeep]);

  const update = (key: string, fn: (t: Turn) => Turn) => setTurns((ts) => ts.map((t) => (t.key === key ? fn(t) : t)));

  const ask = async (q: string) => {
    const text = q.trim();
    if (!text) return;
    abortRef.current?.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    const key = `local-${Date.now()}`;
    setTurns((ts) => [...ts, { key, question: text, steps: [], status: "running" }]);
    setActive(key);
    setQuestion("");
    setAnnounce("Investigating…");
    requestAnimationFrame(() => logEnd.current?.scrollIntoView({ block: "nearest" }));
    let finished = false;
    const onEvent = (ev: InvestigateEvent) => {
      switch (ev.type) {
        case "started":
          update(key, (t) => ({ ...t, investigationId: ev.investigationId, agent: ev.agent }));
          break;
        case "step":
          update(key, (t) => ({ ...t, steps: [...t.steps.filter((s) => s.index !== ev.step.index), ev.step] }));
          setAnnounce(`Step ${ev.step.index}: ${ev.step.label}`);
          break;
        case "answer":
          update(key, (t) => ({ ...t, answer: ev.text, outcome: ev.outcome, validated: ev.validated }));
          break;
        case "done":
          finished = true;
          update(key, (t) => ({ ...t, status: "done", investigationId: t.investigationId ?? ev.investigationId }));
          setAnnounce("Answer ready.");
          break;
        case "error":
          finished = true;
          update(key, (t) => ({ ...t, status: "error", error: cleanMessage(ev.message) }));
          setAnnounce("The investigation stopped.");
          break;
      }
    };
    try {
      await api.ask(id, text, onEvent, ctrl.signal);
      if (!finished && !ctrl.signal.aborted) {
        update(key, (t) => (t.answer ? { ...t, status: "done" } : { ...t, status: "error", error: "The server closed the connection before answering." }));
      }
    } catch (e) {
      if (ctrl.signal.aborted) return;
      update(key, (t) => ({ ...t, status: "error", error: toApiError(e).message }));
      setAnnounce("The investigation stopped.");
    }
  };

  const running = turns.some((t) => t.status === "running" && t.key.startsWith("local-"));
  const current = turns.find((t) => t.key === active) ?? turns[turns.length - 1] ?? null;

  const flags: FlagMap = useMemo(() => {
    const m: FlagMap = new Map();
    for (const f of summary?.findings ?? []) {
      if (f.status === "dismissed" || f.status === "skipped") continue;
      const g = findingGroup(f);
      const risk = g === "compromise" ? "malware" : g === "suspicious" ? "suspicious" : "vuln";
      const prev = m.get(f.versionKey);
      const rank = { malware: 0, suspicious: 1, vuln: 2 };
      if (!prev || rank[risk] < rank[prev]) m.set(f.versionKey, risk);
    }
    return m;
  }, [summary]);

  const evidence = useMemo(
    () => (current ? mergeEvidence([current.evidence, ...current.steps.map((s) => s.evidence)]) : { nodes: [], edges: [] }),
    [current],
  );

  const projectName = summary?.name ?? "this project";

  return (
    <div className="page ask">
      <header className="ask-head">
        <p className="crumb">
          <a href={href.project(id)}>{summary?.name ?? "Project"}</a>
        </p>
        <h1 id="page-title" tabIndex={-1}>
          Ask Taintgraph
        </h1>
        <p className="muted">
          An analyst agent answers from the graph. Every step shows the tool it used, the Cypher it ran and what came back.
        </p>
      </header>

      <p className="visually-hidden" role="status" aria-live="polite">
        {announce}
      </p>

      <div className="ask-grid">
        <section className="chat" aria-labelledby="chat-h">
          <h2 id="chat-h" className="visually-hidden">
            Conversation
          </h2>
          {deepError ? <ErrorState error={deepError} onRetry={loadDeep} title="Couldn't load that investigation." /> : null}
          {turns.length === 0 && !investigationId && (
            <p className="muted chat-empty">Ask a question about {projectName}, or start with one of these.</p>
          )}
          {turns.length === 0 && investigationId && !deepError && <Loading label="Loading the investigation" />}
          <ol className="turns">
            {turns.map((t) => (
              <li key={t.key} className={t.key === current?.key ? "turn current" : "turn"}>
                <p className="q">
                  <span className="visually-hidden">You asked: </span>
                  {t.question}
                </p>
                <div className="a">
                  <div className="a-meta">
                    <span className="agent">{agentLabel(t.agent)}</span>
                    {t.outcome && <OutcomePill outcome={t.outcome} />}
                    {t.status === "running" && <span className="muted small">Working… {t.steps.length ? `${t.steps.length} steps so far` : ""}</span>}
                  </div>
                  {t.answer ? (
                    <Markdown source={t.answer} headingBase={3} />
                  ) : t.status === "running" ? (
                    <Loading label="Reading the graph" compact />
                  ) : null}
                  {t.validated === false && (
                    <p className="note">
                      Some names in the model's answer weren't in the graph results, so this answer was rebuilt from the results.
                    </p>
                  )}
                  {t.status === "error" && (
                    <div className="state state-error" role="alert">
                      <p>{t.error}</p>
                      <button type="button" className="btn btn-small" onClick={() => ask(t.question)} disabled={running}>
                        Try again
                      </button>
                    </div>
                  )}
                  <div className="a-actions">
                    {t.key !== current?.key && (
                      <button type="button" className="btn-link" onClick={() => setActive(t.key)}>
                        Show how I got here
                      </button>
                    )}
                    {t.investigationId && t.status !== "running" && (
                      <a href={href.ask(id, t.investigationId)} className="small">
                        Link to this answer
                      </a>
                    )}
                  </div>
                </div>
              </li>
            ))}
          </ol>
          <div ref={logEnd} />

          {summaryError ? (
            <ErrorState error={summaryError} onRetry={loadSummary} title="Couldn't load this project's details." />
          ) : !summary ? (
            <Loading label="Preparing suggestions" compact />
          ) : (
            <ul className="chips" aria-label="Suggested questions">
              {suggestions(summary).map((s) => (
                <li key={s}>
                  <button type="button" className="chip" onClick={() => ask(s)} disabled={running}>
                    {s}
                  </button>
                </li>
              ))}
            </ul>
          )}

          <form
            className="ask-form"
            onSubmit={(e) => {
              e.preventDefault();
              void ask(question);
            }}
          >
            <label htmlFor="ask-input">Your question</label>
            <div className="inline-field">
              <input
                id="ask-input"
                type="text"
                value={question}
                onChange={(e) => setQuestion(e.target.value)}
                placeholder="Which packages could a hijacked maintainer reach?"
                autoComplete="off"
              />
              <button type="submit" className="btn btn-primary" disabled={running || !question.trim()}>
                {running ? "Working…" : "Ask"}
              </button>
            </div>
          </form>
        </section>

        <aside className="trace" aria-labelledby="trace-h">
          <h2 id="trace-h">How I got here</h2>
          {!current ? (
            <p className="muted">Each step the agent takes shows up here, with the query it ran against the graph.</p>
          ) : (
            <>
              <p className="trace-q muted small">For: {current.question}</p>
              <Steps turn={current} />
              <h3 className="evidence-h">Evidence</h3>
              <EvidenceGraph evidence={evidence} projectName={projectName} flags={flags} />
            </>
          )}
        </aside>
      </div>
    </div>
  );
}
