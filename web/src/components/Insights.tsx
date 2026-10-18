import { useEffect, useState } from "react";
import type { InsightsView } from "@api/types";
import { api } from "../api";

const pct = (x: number) => `${Math.round(x * 100)}%`;
const scrollTo = (id: string) => {
  const el = document.getElementById(id);
  if (el) window.scrollTo({ top: el.getBoundingClientRect().top + window.scrollY - 64, behavior: "smooth" });
};

interface Card {
  value: string;
  label: string;
  detail?: string;
  technique: string;
  hot?: boolean;
  go?: string; // id of the section with the details
  run?: () => void; // an action instead (the worm card runs the simulation)
}

function cards(d: InsightsView, onSimulate: (login: string) => void): Card[] {
  return [
    {
      value: String(d.compromised),
      label: d.compromised === 1 ? "malicious version installed" : "malicious versions installed",
      detail: `out of ${d.versions.toLocaleString("en-US")} versions and ${d.edges.toLocaleString("en-US")} dependency edges`,
      technique: "AFFECTS edges",
      hot: d.compromised > 0,
      go: "findings-h",
    },
    d.deepest
      ? { value: `${d.deepest.hops} ${d.deepest.hops === 1 ? "hop" : "hops"}`, label: `deepest route, to ${d.deepest.name}@${d.deepest.version}`, detail: d.deepest.via.length ? `via ${d.deepest.via.join(" → ")}` : "a direct dependency", technique: "shortestPath", hot: true, go: "graph-h" }
      : { value: "0", label: "routes to malware", detail: "nothing malicious reaches the app", technique: "shortestPath", go: "graph-h" },
    d.topAccount
      ? { value: pct(d.topAccount.share), label: `of the tree is publishable by ${d.topAccount.login}`, detail: `${d.topAccount.versions} versions${d.topAccount.flagged ? ", including a flagged one" : ""}`, technique: "PageRank", hot: d.topAccount.flagged, go: "accounts-h" }
      : { value: "–", label: "no maintainer data", technique: "PageRank" },
    d.worm
      ? { value: pct(d.worm.poisonedShare), label: `poisoned if ${d.worm.start} is phished`, detail: `a worm takes over ${d.worm.accounts} accounts in ${d.worm.waves} waves. Click to watch it spread`, technique: "multi-hop traversal", hot: d.worm.poisonedShare >= 0.25, run: () => onSimulate(d.worm!.start) }
      : { value: "–", label: "worm simulation unavailable", technique: "multi-hop traversal" },
    d.topTeam
      ? { value: pct(d.topTeam.share), label: `publishable by one maintainer team`, detail: `${d.topTeam.accounts.join(", ")}${d.topTeam.size > 3 ? ` +${d.topTeam.size - 3}` : ""}`, technique: "community detection", hot: d.topTeam.flagged, go: "teams-h" }
      : { value: "–", label: "no maintainer teams", technique: "community detection" },
    { value: `${d.network.accounts}`, label: `of ${d.network.totalAccounts} accounts in one network`, detail: "the furthest a self-spreading worm could ever reach", technique: "connected components (WCC)", go: "teams-h" },
  ];
}

export default function Insights({ projectId, scanId, onSimulate }: { projectId: string; scanId: string; onSimulate: (login: string) => void }) {
  const [d, setD] = useState<InsightsView | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    let live = true;
    setD(null);
    setFailed(false);
    api.insights(projectId).then((x) => live && setD(x), () => live && setFailed(true));
    return () => {
      live = false;
    };
  }, [projectId, scanId]);
  if (failed) return null;
  return (
    <section className="insights" aria-labelledby="insights-h" aria-busy={!d}>
      <div className="insights-head">
        <h2 id="insights-h">What the graph shows</h2>
        <p className="muted small">Each number is a FalkorDB query or graph algorithm run over this project. The tag says which.</p>
      </div>
      <div className="insight-grid">
        {d
          ? cards(d, onSimulate).map((c) => (
              <button type="button" key={c.technique} className={`insight${c.hot ? " insight-hot" : ""}`} onClick={() => (c.run ? c.run() : c.go && scrollTo(c.go))} disabled={!c.go && !c.run}>
                <span className="insight-tag">{c.technique}</span>
                <span className="insight-value">{c.value}</span>
                <span className="insight-label">{c.label}</span>
                {c.detail && <span className="insight-detail">{c.detail}</span>}
              </button>
            ))
          : Array.from({ length: 6 }, (_, i) => <div key={i} className="insight insight-loading" aria-hidden="true" />)}
      </div>
      {d && d.fixes > 0 && (
        <button type="button" className="btn btn-primary insights-fix" onClick={() => scrollTo("fix-h")}>
          {d.incident ? "See the fix plan and incident steps" : "See the fix plan"} ({d.fixes} {d.fixes === 1 ? "change" : "changes"})
        </button>
      )}
    </section>
  );
}
