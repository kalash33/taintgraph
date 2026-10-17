import { useEffect, useState } from "react";
import type { TeamsView } from "@api/types";
import { api } from "../api";

/** Maintainer teams (community detection) and the largest connected maintainer network (connected components). */
export default function Teams({ projectId, scanId, onSimulate }: { projectId: string; scanId: string; onSimulate: (login: string) => void }) {
  const [t, setT] = useState<TeamsView | null>(null);
  useEffect(() => {
    let live = true;
    api.teams(projectId).then((x) => live && setT(x), () => live && setT(null));
    return () => {
      live = false;
    };
  }, [projectId, scanId]);
  if (!t || !t.teams.length) return null;
  const max = Math.max(...t.teams.map((x) => x.share), 0.01);
  return (
    <section className="teams" aria-labelledby="teams-h">
      <h2 id="teams-h">Maintainer teams</h2>
      <p className="muted small">
        Found by community detection over who maintains what. Teams often share tokens and CI, so one phished account can open the whole team.
      </p>
      <ol className="team-list">
        {t.teams.slice(0, 5).map((x) => (
          <li key={x.id} className={x.flagged ? "team team-flagged" : "team"}>
            <div className="team-head">
              <span className="team-names">
                {x.accounts.slice(0, 3).join(", ")}
                {x.accounts.length > 3 && <span className="muted"> +{x.accounts.length - 3}</span>}
              </span>
              <button type="button" className="btn btn-small" onClick={() => onSimulate(x.accounts[0])} aria-label={`Simulate a takeover of ${x.accounts[0]}`}>
                Simulate
              </button>
            </div>
            {x.flagged && <div className="flag-mark">Can publish a flagged package</div>}
            <div className="team-bar" aria-hidden="true">
              <span style={{ width: `${Math.max(3, (x.share / max) * 100)}%` }} />
            </div>
            <div className="muted small">
              {x.versions} versions · {(x.share * 100).toFixed(0)}% · e.g. {x.packages.slice(0, 3).join(", ")}
            </div>
          </li>
        ))}
      </ol>
      {t.network.accounts > 1 && (
        <p className="team-network small">
          <strong>
            {t.network.accounts} of {t.network.totalAccounts}
          </strong>{" "}
          accounts form one connected maintainer network (connected components): the furthest a self-spreading worm could reach.
        </p>
      )}
    </section>
  );
}
