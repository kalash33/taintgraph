import { useEffect, useMemo, useRef, useState } from "react";
import type { FindingStatus, FindingView, RuleView } from "@api/types";
import {
  api,
  compareFindings,
  findingGroup,
  severityLabel,
  shortKey,
  signalLabel,
  STATUS_LABEL,
  toApiError,
  type Verdict,
} from "../api";

export interface FocusRequest {
  versionKey: string;
  nonce: number;
}

const VERDICTS: { verdict: Verdict; label: string }[] = [
  { verdict: "confirmed", label: "Real threat" },
  { verdict: "dismissed", label: "Not a threat" },
  { verdict: "accepted", label: "Accept risk" },
];

function StatusPill({ status }: { status: FindingStatus }) {
  return <span className={`pill status-${status}`}>{STATUS_LABEL[status]}</span>;
}

export function Route({ path, projectName }: { path: string[]; projectName: string }) {
  if (!path.length) return null;
  return (
    <ol className="route" aria-label="Route from your project to this package">
      {path.map((k, i) => (
        <li key={`${k}-${i}`} className={i === 0 ? "route-root" : i === path.length - 1 ? "route-end" : undefined}>
          {i === 0 && k.startsWith("project/") ? <span>{projectName}</span> : <code>{shortKey(k, projectName)}</code>}
        </li>
      ))}
    </ol>
  );
}

function RuleNotice({ rule }: { rule: RuleView }) {
  const [state, setState] = useState<"idle" | "busy" | "active" | "error">(rule.status === "active" ? "active" : "idle");
  const [err, setErr] = useState("");
  const conf = Math.round((rule.confidence <= 1 ? rule.confidence * 100 : rule.confidence) || 0);
  return (
    <div className="rule-notice">
      <p>
        Taintgraph learned a rule: when <strong>{signalLabel(rule.when)}</strong> then{" "}
        <strong>{rule.then === "escalate" ? "escalate" : "skip it"}</strong> ({conf}% confidence)
      </p>
      {state === "active" ? (
        <p className="ok small" role="status">
          Rule active. Future scans will apply it.
        </p>
      ) : (
        <button
          type="button"
          className="btn btn-small"
          disabled={state === "busy"}
          onClick={async () => {
            setState("busy");
            try {
              await api.activateRule(rule.id);
              setState("active");
            } catch (e) {
              setErr(toApiError(e).message);
              setState("error");
            }
          }}
        >
          {state === "busy" ? "Activating…" : "Activate"}
        </button>
      )}
      {state === "error" && (
        <p className="error-text small" role="alert">
          {err}
        </p>
      )}
    </div>
  );
}

interface CardProps {
  finding: FindingView;
  projectName: string;
  highlighted: boolean;
  headingLevel: 3 | 4;
  onVerdict: (f: FindingView, verdict: Verdict, note: string) => Promise<RuleView | undefined>;
  headingRef?: (el: HTMLHeadingElement | null) => void;
}

export function FindingCard({ finding: f, projectName, highlighted, headingLevel, onVerdict, headingRef }: CardProps) {
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState<Verdict | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [rule, setRule] = useState<RuleView | null>(null);
  const [allAdvisories, setAllAdvisories] = useState(false);
  const localHeading = useRef<HTMLHeadingElement | null>(null);
  const H = `h${headingLevel}` as "h3";
  const group = findingGroup(f);
  const advisories = allAdvisories ? f.advisories : f.advisories.slice(0, 3);
  const noteId = `note-${f.id}`;

  const act = async (v: Verdict) => {
    setBusy(v);
    setError(null);
    try {
      const proposed = await onVerdict(f, v, note.trim());
      if (proposed) setRule(proposed);
      setNote("");
      requestAnimationFrame(() => localHeading.current?.focus({ preventScroll: true }));
    } catch (e) {
      setError(toApiError(e).message);
    } finally {
      setBusy(null);
    }
  };

  return (
    <article
      id={`finding-${f.id}`}
      className={`finding sev-${f.severity} grp-${group}${highlighted ? " highlighted" : ""}`}
      aria-labelledby={`finding-h-${f.id}`}
    >
      <div className="finding-head">
        <H
          id={`finding-h-${f.id}`}
          tabIndex={-1}
          ref={(el) => {
            localHeading.current = el;
            headingRef?.(el);
          }}
        >
          {f.title}
        </H>
        <StatusPill status={f.status} />
      </div>
      <p className="finding-meta">
        <code className="pkg">
          {f.name}@{f.version}
        </code>
        <span className={`sev sev-text-${f.severity}`}>{severityLabel(f.severity)}</span>
        <span className="signal">{signalLabel(f.signal)}</span>
      </p>
      {f.detail && <p className="finding-detail">{f.detail}</p>}
      <div className="finding-route">
        <p className="label-sm">How it reaches you</p>
        <Route path={f.path} projectName={projectName} />
      </div>
      {f.advisories.length > 0 && (
        <div className="advisories">
          <p className="label-sm">Advisories</p>
          <ul>
            {advisories.map((a) => (
              <li key={a.id}>
                {/^https?:\/\//.test(a.url) ? (
                  <a href={a.url} target="_blank" rel="noopener noreferrer">
                    <code>{a.id}</code>
                  </a>
                ) : (
                  <code>{a.id}</code>
                )}{" "}
                <span>{a.summary}</span>
              </li>
            ))}
          </ul>
          {f.advisories.length > 3 && (
            <button type="button" className="btn-link" aria-expanded={allAdvisories} onClick={() => setAllAdvisories((v) => !v)}>
              {allAdvisories ? "Show fewer" : `Show ${f.advisories.length - 3} more`}
            </button>
          )}
        </div>
      )}
      {f.fix && (
        <p className="fix">
          <span className="label-sm">Fix</span> {f.fix}
        </p>
      )}
      {f.statusNote && <p className="status-note">{f.statusNote}</p>}
      {f.status !== "skipped" && (
        <div className="verdict-actions">
          <div className="field note-field">
            <label htmlFor={noteId}>Note (optional)</label>
            <input id={noteId} type="text" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Why you decided this" />
          </div>
          <div className="verdict-buttons" role="group" aria-label={`Your verdict on ${f.name}@${f.version}`}>
            {VERDICTS.map((v) => (
              <button
                key={v.verdict}
                type="button"
                className={`btn btn-small${f.status === v.verdict ? " is-current" : ""}${v.verdict === "confirmed" ? " btn-danger" : ""}`}
                aria-pressed={f.status === v.verdict}
                disabled={busy !== null}
                onClick={() => act(v.verdict)}
              >
                {busy === v.verdict ? "Saving…" : v.label}
              </button>
            ))}
          </div>
        </div>
      )}
      {error && (
        <p className="error-text" role="alert">
          {error}
        </p>
      )}
      {rule && <RuleNotice rule={rule} />}
    </article>
  );
}

const VULN_PAGE = 12;

export default function Findings({
  findings,
  projectName,
  focusRequest,
  onStatusChange,
}: {
  findings: FindingView[];
  projectName: string;
  focusRequest: FocusRequest | null;
  onStatusChange: (id: string, status: FindingStatus, note: string) => void;
}) {
  const [announce, setAnnounce] = useState("");
  const [highlightId, setHighlightId] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [showAllVulns, setShowAllVulns] = useState(false);
  const [skippedOpen, setSkippedOpen] = useState(false);
  const headings = useRef(new Map<string, HTMLHeadingElement>());

  const sorted = useMemo(() => [...findings].sort(compareFindings), [findings]);
  const main = sorted.filter((f) => f.status !== "skipped" && findingGroup(f) !== "vulnerability");
  const vulns = sorted.filter((f) => f.status !== "skipped" && findingGroup(f) === "vulnerability");
  const skipped = sorted.filter((f) => f.status === "skipped");
  const visibleVulns = showAllVulns ? vulns : vulns.slice(0, VULN_PAGE);

  // respond to "show me this package" requests from the graph
  const pendingFocus = useRef<string | null>(null);
  useEffect(() => {
    if (!focusRequest) return;
    const candidates = sorted.filter((f) => f.versionKey === focusRequest.versionKey);
    const target = candidates.find((f) => f.status !== "skipped") ?? candidates[0];
    if (!target) {
      setAnnounce("No finding is listed for that package.");
      return;
    }
    if (target.status === "skipped") setSkippedOpen(true);
    else if (findingGroup(target) === "vulnerability") {
      setExpanded((s) => new Set(s).add(target.id));
      if (vulns.findIndex((v) => v.id === target.id) >= VULN_PAGE) setShowAllVulns(true);
    }
    pendingFocus.current = target.id;
    setHighlightId(target.id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusRequest]);

  useEffect(() => {
    const id = pendingFocus.current;
    if (!id) return;
    const el = document.getElementById(`finding-${id}`) ?? document.getElementById(`skipped-${id}`);
    if (!el) return;
    pendingFocus.current = null;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    el.scrollIntoView({ block: "center", behavior: reduce ? "auto" : "smooth" });
    const h = headings.current.get(id);
    (h ?? el).focus?.({ preventScroll: true });
    const t = window.setTimeout(() => setHighlightId((cur) => (cur === id ? null : cur)), 4000);
    return () => window.clearTimeout(t);
  });

  const onVerdict = async (f: FindingView, verdict: Verdict, note: string) => {
    const res = await api.verdict(f.id, verdict, note || undefined);
    onStatusChange(f.id, verdict, note);
    const label = STATUS_LABEL[verdict];
    setAnnounce(
      `Marked ${f.name}@${f.version} as ${label}.${res.proposedRule ? " Taintgraph learned a rule from this; you can activate it below the card." : ""}`,
    );
    return res.proposedRule;
  };

  const cardProps = (f: FindingView) => ({
    finding: f,
    projectName,
    highlighted: highlightId === f.id,
    onVerdict,
    headingRef: (el: HTMLHeadingElement | null) => {
      if (el) headings.current.set(f.id, el);
      else headings.current.delete(f.id);
    },
  });

  return (
    <div className="findings">
      <p className="visually-hidden" role="status" aria-live="polite">
        {announce}
      </p>
      {findings.length === 0 && (
        <div className="state state-empty">
          <p className="state-title">Nothing dangerous found.</p>
          <p>No malware, suspicious releases or known vulnerabilities touch this project's packages right now.</p>
        </div>
      )}
      {main.length > 0 && (
        <div className="finding-list">
          {main.map((f) => (
            <FindingCard key={f.id} {...cardProps(f)} headingLevel={3} />
          ))}
        </div>
      )}
      {findings.length > 0 && main.length === 0 && (
        <p className="muted">No malware or suspicious releases. Only ordinary vulnerabilities below.</p>
      )}

      {vulns.length > 0 && (
        <section className="vuln-group" aria-labelledby="vulns-h">
          <h3 id="vulns-h">Known vulnerabilities ({vulns.length})</h3>
          <ul className="vuln-rows">
            {visibleVulns.map((f) => {
              const open = expanded.has(f.id);
              const hops = Math.max(0, f.path.length - 1);
              return (
                <li key={f.id} id={open ? undefined : `finding-${f.id}`}>
                  <button
                    type="button"
                    className={`vuln-row sev-${f.severity}${highlightId === f.id && !open ? " highlighted" : ""}`}
                    aria-expanded={open}
                    aria-controls={open ? `finding-${f.id}` : undefined}
                    onClick={() =>
                      setExpanded((s) => {
                        const n = new Set(s);
                        if (n.has(f.id)) n.delete(f.id);
                        else n.add(f.id);
                        return n;
                      })
                    }
                  >
                    <code className="pkg">
                      {f.name}@{f.version}
                    </code>
                    <span className={`sev sev-text-${f.severity}`}>{severityLabel(f.severity)}</span>
                    <span className="muted small">
                      {f.advisories.length} {f.advisories.length === 1 ? "advisory" : "advisories"}
                    </span>
                    <span className="muted small">
                      {hops} {hops === 1 ? "hop" : "hops"}
                    </span>
                    {f.status !== "open" && <StatusPill status={f.status} />}
                  </button>
                  {open && <FindingCard {...cardProps(f)} headingLevel={4} />}
                </li>
              );
            })}
          </ul>
          {vulns.length > VULN_PAGE && (
            <button type="button" className="btn-link" aria-expanded={showAllVulns} onClick={() => setShowAllVulns((v) => !v)}>
              {showAllVulns ? `Show the first ${VULN_PAGE}` : `Show all ${vulns.length}`}
            </button>
          )}
        </section>
      )}

      {skipped.length > 0 && (
        <details className="skipped-group" open={skippedOpen} onToggle={(e) => setSkippedOpen((e.target as HTMLDetailsElement).open)}>
          <summary>Skipped by memory ({skipped.length})</summary>
          <ul>
            {skipped.map((f) => (
              <li key={f.id} id={`skipped-${f.id}`} tabIndex={-1} className={highlightId === f.id ? "highlighted" : undefined}>
                <code>
                  {f.name}@{f.version}
                </code>{" "}
                <span className="muted small">{signalLabel(f.signal)}</span>
                {f.statusNote && <span className="status-note-inline"> · {f.statusNote}</span>}
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}
