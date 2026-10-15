import { useEffect, useRef, useState } from "react";
import type { AccountView, WormResult } from "@api/types";
import { api, KIND_LABEL, pct, toApiError } from "../api";
import { ErrorState } from "./States";

export type SimState =
  | { status: "idle" }
  | { status: "loading"; login: string }
  | { status: "running" | "done"; login: string; result: WormResult; wave: number }
  | { status: "error"; login: string; error: unknown };

export default function Accounts({
  projectId,
  top,
  total,
  sim,
  onSimulate,
  onReset,
}: {
  projectId: string;
  top: AccountView[];
  total: number;
  sim: SimState;
  onSimulate: (login: string) => void;
  onReset: () => void;
}) {
  const [all, setAll] = useState<AccountView[] | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [moreError, setMoreError] = useState<string | null>(null);
  const bannerRef = useRef<HTMLDivElement>(null);
  const simRef = useRef<HTMLDivElement>(null);

  const list = all ?? top.slice(0, 10);
  const maxShare = Math.max(0.0001, ...list.map((a) => a.share));

  const loadMore = async () => {
    setLoadingMore(true);
    setMoreError(null);
    try {
      setAll(await api.accounts(projectId));
    } catch (e) {
      setMoreError(toApiError(e).message);
    } finally {
      setLoadingMore(false);
    }
  };

  const finished = sim.status === "done";
  useEffect(() => {
    if (finished) bannerRef.current?.focus();
  }, [finished]);

  useEffect(() => {
    if (sim.status === "loading") {
      simRef.current?.scrollIntoView({ block: "nearest" });
    }
  }, [sim.status]);

  const shownWaves = sim.status === "running" || sim.status === "done" ? sim.result.waves.filter((w) => w.wave <= sim.wave) : [];

  return (
    <div className="accounts">
      <p className="muted">
        {all ? `Top ${list.length} of ${total} accounts` : `Top ${Math.min(10, top.length)} of ${total} accounts`}, ranked by how
        much of your tree each one can publish.
      </p>
      {list.length === 0 ? (
        <p className="muted">No publishing accounts were found for this project's packages.</p>
      ) : (
        <ol className="account-list">
          {list.map((a, i) => {
            const active = sim.status !== "idle" && sim.login === a.login;
            return (
              <li key={a.key} className={active ? "account active" : "account"}>
                <span className="rank" aria-hidden="true">
                  {i + 1}
                </span>
                <div className="account-body">
                  <div className="account-top">
                    <code className="login">{a.login}</code>
                    <span className="kind">{KIND_LABEL[a.kind] ?? a.kind}</span>
                    {a.flagged && <span className="flag-mark">Published a flagged version</span>}
                  </div>
                  <div className="reach" aria-hidden="true">
                    <span style={{ width: `${Math.max(2, (a.share / maxShare) * 100)}%` }} className={a.flagged ? "flagged" : undefined} />
                  </div>
                  <p className="account-stats">
                    {a.versions} {a.versions === 1 ? "version" : "versions"} · {pct(a.share)}
                    <span className="visually-hidden"> of this project's packages</span>
                  </p>
                </div>
                <button
                  type="button"
                  className="btn btn-small"
                  onClick={() => onSimulate(a.login)}
                  disabled={sim.status === "loading" || sim.status === "running"}
                  aria-label={`Simulate takeover of ${a.login}`}
                >
                  Simulate takeover
                </button>
              </li>
            );
          })}
        </ol>
      )}
      {!all && total > 10 && (
        <button type="button" className="btn-link" onClick={loadMore} disabled={loadingMore}>
          {loadingMore ? "Loading accounts…" : "Show top 25"}
        </button>
      )}
      {moreError && (
        <p className="error-text" role="alert">
          {moreError}
        </p>
      )}

      {sim.status !== "idle" && (
        <div className="sim" ref={simRef} aria-labelledby="sim-h">
          <h3 id="sim-h">
            Takeover of <code>{sim.login}</code>
          </h3>
          {sim.status === "loading" && (
            <p role="status" className="muted">
              Simulating how a worm would spread from this account…
            </p>
          )}
          {sim.status === "error" && <ErrorState error={sim.error} onRetry={() => onSimulate(sim.login)} />}
          {(sim.status === "running" || sim.status === "done") && (
            <>
              <p className="muted small">
                A worm steals this account's token, publishes poisoned versions, then reuses every token it finds on
                infected machines. Poisoned packages turn red in the graph.
              </p>
              <ol className="waves">
                {shownWaves.map((w) => (
                  <li key={w.wave}>
                    <span className="wave-n">Wave {w.wave}</span>
                    <span>
                      {w.accounts.length} {w.accounts.length === 1 ? "account" : "accounts"} compromised, {w.poisoned.length}{" "}
                      {w.poisoned.length === 1 ? "package" : "packages"} poisoned
                    </span>
                    {w.accounts.length > 0 && (
                      <span className="wave-accounts">
                        {w.accounts.slice(0, 6).map((l) => (
                          <code key={l}>{l}</code>
                        ))}
                        {w.accounts.length > 6 && <span className="muted small">+{w.accounts.length - 6} more</span>}
                      </span>
                    )}
                  </li>
                ))}
              </ol>
              {sim.status === "running" && (
                <p className="muted small" aria-hidden="true">
                  Spreading…
                </p>
              )}
              {sim.status === "done" && (
                <div className="sim-banner" tabIndex={-1} ref={bannerRef} role="status">
                  <strong>
                    {sim.result.waves.length} {sim.result.waves.length === 1 ? "wave" : "waves"} later: {pct(sim.result.poisonedShare)} of your
                    packages poisoned, {sim.result.compromisedAccounts}{" "}
                    {sim.result.compromisedAccounts === 1 ? "account" : "accounts"} compromised
                  </strong>
                </div>
              )}
              {sim.status === "done" && (
                <button type="button" className="btn-link" onClick={onReset}>
                  Clear simulation
                </button>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
