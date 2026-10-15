import { useCallback, useEffect, useState } from "react";
import type { MemoryView, RuleView, TaskView } from "@api/types";
import { api, formatWhen, isoTime, shortKey, signalLabel, STATUS_LABEL, toApiError } from "../api";
import { href } from "../App";
import { Empty, ErrorState, Loading } from "./States";

const TASK_STATUS: Record<TaskView["status"], string> = { open: "Waiting", claimed: "In progress", done: "Done", error: "Failed" };
const TASK_TYPE: Record<TaskView["type"], string> = { analyze: "Analyze findings", report: "Write report" };
const AGENT: Record<string, string> = { scout: "Scout", analyst: "Analyst", reporter: "Reporter" };
const agentName = (a?: string) => (a ? (AGENT[a.toLowerCase()] ?? a) : "");

function When({ t }: { t: number }) {
  return <time dateTime={isoTime(t)}>{formatWhen(t)}</time>;
}

function RuleRow({ rule, onActivated }: { rule: RuleView; onActivated: (id: string) => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const conf = Math.round((rule.confidence <= 1 ? rule.confidence * 100 : rule.confidence) || 0);
  return (
    <li className="rule">
      <p className="rule-text">
        When <strong>{signalLabel(rule.when)}</strong>, then <strong>{rule.then === "escalate" ? "escalate" : "skip it"}</strong>
      </p>
      <span className={rule.status === "active" ? "pill pill-clean" : "pill pill-neutral"}>{rule.status === "active" ? "Active" : "Proposed"}</span>
      <span className="muted small">{conf}% confidence</span>
      {rule.learnedFrom.length > 0 && (
        <span className="muted small">
          learned from {rule.learnedFrom.length} {rule.learnedFrom.length === 1 ? "verdict" : "verdicts"}
        </span>
      )}
      {rule.status === "proposed" && (
        <button
          type="button"
          className="btn btn-small"
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            setErr(null);
            try {
              await api.activateRule(rule.id);
              onActivated(rule.id);
            } catch (e) {
              setErr(toApiError(e).message);
            } finally {
              setBusy(false);
            }
          }}
        >
          {busy ? "Activating…" : "Activate"}
        </button>
      )}
      {err && (
        <p className="error-text small" role="alert">
          {err}
        </p>
      )}
    </li>
  );
}

export default function Memory() {
  const [mem, setMem] = useState<MemoryView | null>(null);
  const [error, setError] = useState<unknown>(null);

  const load = useCallback(() => {
    setError(null);
    api.memory().then(setMem, setError);
  }, []);
  useEffect(() => {
    document.title = "Memory · Upstream";
    load();
  }, [load]);

  return (
    <div className="page memory">
      <h1 id="page-title" tabIndex={-1}>
        Memory
      </h1>
      <p className="lede">
        What Upstream remembers between scans: your verdicts, the rules it learned from them, past questions, and the work its
        agents handed to each other.
      </p>
      {error ? (
        <ErrorState error={error} onRetry={load} />
      ) : !mem ? (
        <Loading label="Loading memory" />
      ) : (
        <div className="memory-grid">
          <section aria-labelledby="inv-h">
            <h2 id="inv-h">Past investigations</h2>
            {mem.investigations.length === 0 ? (
              <Empty title="No questions asked yet.">
                <p>Open a project and choose Ask Upstream.</p>
              </Empty>
            ) : (
              <ul className="inv-list">
                {[...mem.investigations]
                  .sort((a, b) => b.startedAt - a.startedAt)
                  .map((i) => (
                    <li key={i.id}>
                      <a href={href.ask(i.projectId, i.id)}>{i.question}</a>
                      <span className="muted small">
                        {i.projectName} · <When t={i.startedAt} /> · {i.agent === "built-in" ? "built-in investigator" : i.agent}
                      </span>
                    </li>
                  ))}
              </ul>
            )}
          </section>

          <section aria-labelledby="rules-h">
            <h2 id="rules-h">Learned rules</h2>
            {mem.rules.length === 0 ? (
              <Empty title="No rules yet.">
                <p>When you mark findings as real threats or not, Upstream proposes rules from the pattern.</p>
              </Empty>
            ) : (
              <ul className="rule-list">
                {mem.rules.map((r) => (
                  <RuleRow
                    key={r.id}
                    rule={r}
                    onActivated={(rid) =>
                      setMem((m) => (m ? { ...m, rules: m.rules.map((x) => (x.id === rid ? { ...x, status: "active" } : x)) } : m))
                    }
                  />
                ))}
              </ul>
            )}
          </section>

          <section aria-labelledby="verdicts-h" className="span-2">
            <h2 id="verdicts-h">Verdicts</h2>
            {mem.verdicts.length === 0 ? (
              <Empty title="No verdicts yet.">
                <p>Mark a finding as Real threat, Not a threat or Accept risk and it shows up here.</p>
              </Empty>
            ) : (
              <div className="table-scroll" tabIndex={0} role="region" aria-label="Verdicts table, scrollable">
                <table>
                  <thead>
                    <tr>
                      <th scope="col">Version</th>
                      <th scope="col">Signal</th>
                      <th scope="col">Verdict</th>
                      <th scope="col">Note</th>
                      <th scope="col">When</th>
                    </tr>
                  </thead>
                  <tbody>
                    {[...mem.verdicts]
                      .sort((a, b) => b.at - a.at)
                      .map((v) => (
                        <tr key={`${v.findingId}-${v.at}`}>
                          <td>
                            <code>{shortKey(v.versionKey)}</code>
                          </td>
                          <td>{signalLabel(v.signal)}</td>
                          <td>
                            <span className={`pill status-${v.verdict}`}>{STATUS_LABEL[v.verdict] ?? v.verdict}</span>
                          </td>
                          <td>{v.note || <span className="muted">No note</span>}</td>
                          <td>
                            <When t={v.at} />
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <section aria-labelledby="tasks-h" className="span-2">
            <h2 id="tasks-h">Agent handoffs</h2>
            <p className="muted">Scout finds new advisories, hands analysis to the Analyst, and the Reporter writes it up.</p>
            {mem.tasks.length === 0 ? (
              <Empty title="No handoffs yet." />
            ) : (
              <ol className="timeline">
                {[...mem.tasks]
                  .sort((a, b) => b.createdAt - a.createdAt)
                  .map((t) => (
                    <li key={t.id} className={`task task-${t.status}`}>
                      <span className="task-dot" aria-hidden="true" />
                      <div>
                        <p className="task-title">
                          <strong>{TASK_TYPE[t.type] ?? t.type}</strong> for {agentName(t.forAgent)}
                          <span className={`pill task-pill-${t.status}`}>{TASK_STATUS[t.status] ?? t.status}</span>
                        </p>
                        <p className="muted small">
                          {t.projectName}
                          {t.claimedBy ? ` · claimed by ${agentName(t.claimedBy)}` : ""} · created <When t={t.createdAt} />
                          {t.doneAt ? (
                            <>
                              {" "}
                              · done <When t={t.doneAt} />
                            </>
                          ) : null}
                        </p>
                      </div>
                    </li>
                  ))}
              </ol>
            )}
          </section>
        </div>
      )}
    </div>
  );
}
