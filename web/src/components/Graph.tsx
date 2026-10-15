import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { DependencyGraph, GraphNode } from "@api/types";
import { truncate } from "../api";

type Risk = GraphNode["risk"];
const RISK_RANK: Record<string, number> = { malware: 0, suspicious: 1, vuln: 2 };
export const RISK_LABEL: Record<string, string> = {
  malware: "Malware",
  suspicious: "Suspicious",
  vuln: "Known vulnerability",
};

interface Placed {
  node: GraphNode;
  x: number;
  y: number;
  size: number;
  parent: string | null;
}

interface Layout {
  placed: Map<string, Placed>;
  width: number;
  height: number;
  edges: { from: Placed; to: Placed; infected: boolean }[];
  labels: { key: string; x: number; y: number; text: string; anchor: "middle" | "end"; risk: Risk; root: boolean }[];
}

const COL_W = 170;
const PAD_L = 84;
const PAD_R = 24;
const PAD_Y = 34;

/** Isotonic regression (pool adjacent violators): least-squares non-decreasing fit. */
function pava(z: number[]): number[] {
  const vals: number[] = [];
  const wts: number[] = [];
  for (const v of z) {
    vals.push(v);
    wts.push(1);
    while (vals.length > 1 && vals[vals.length - 2] > vals[vals.length - 1]) {
      const v2 = vals.pop()!;
      const w2 = wts.pop()!;
      const v1 = vals.pop()!;
      const w1 = wts.pop()!;
      vals.push((v1 * w1 + v2 * w2) / (w1 + w2));
      wts.push(w1 + w2);
    }
  }
  const out: number[] = [];
  vals.forEach((v, i) => {
    for (let k = 0; k < wts[i]; k++) out.push(v);
  });
  return out;
}

function computeLayout(graph: DependencyGraph, keep: Set<string> | null, infectedSet: Set<string>): Layout {
  const nodes = keep ? graph.nodes.filter((n) => keep.has(n.key)) : graph.nodes;
  const byKey = new Map(nodes.map((n) => [n.key, n]));
  const parent = new Map<string, string>();
  for (const e of graph.edges) {
    if (byKey.has(e.from) && byKey.has(e.to) && !parent.has(e.from)) parent.set(e.from, e.to);
  }
  // subtree size
  const size = new Map<string, number>();
  const sorted = [...nodes].sort((a, b) => b.depth - a.depth);
  for (const n of nodes) size.set(n.key, 1);
  for (const n of sorted) {
    const p = parent.get(n.key);
    if (p) size.set(p, (size.get(p) ?? 1) + (size.get(n.key) ?? 1));
  }

  const maxDepth = nodes.reduce((m, n) => Math.max(m, n.depth), 0);
  const cols = new Map<number, GraphNode[]>();
  for (const n of nodes) {
    const list = cols.get(n.depth) ?? [];
    list.push(n);
    cols.set(n.depth, list);
  }
  const count = nodes.length;
  const gap = count > 1200 ? 6 : count > 500 ? 8 : count > 150 ? 11 : count > 40 ? 16 : 24;

  const y = new Map<string, number>();
  for (let d = 0; d <= maxDepth; d++) {
    const col = cols.get(d) ?? [];
    if (!col.length) continue;
    const desired = (n: GraphNode) => {
      const p = parent.get(n.key);
      return p !== undefined ? (y.get(p) ?? 0) : 0;
    };
    col.sort((a, b) => desired(a) - desired(b) || (size.get(b.key) ?? 0) - (size.get(a.key) ?? 0) || a.name.localeCompare(b.name));
    const z = col.map((n, i) => desired(n) - i * gap);
    const fit = pava(z);
    col.forEach((n, i) => y.set(n.key, fit[i] + i * gap));
  }
  let minY = Infinity;
  let maxY = -Infinity;
  for (const v of y.values()) {
    minY = Math.min(minY, v);
    maxY = Math.max(maxY, v);
  }
  if (!Number.isFinite(minY)) {
    minY = 0;
    maxY = 0;
  }

  const placed = new Map<string, Placed>();
  for (const n of nodes) {
    placed.set(n.key, {
      node: n,
      x: PAD_L + (maxDepth - n.depth) * COL_W,
      y: PAD_Y + (y.get(n.key) ?? 0) - minY,
      size: size.get(n.key) ?? 1,
      parent: parent.get(n.key) ?? null,
    });
  }

  const edges: Layout["edges"] = [];
  for (const [k, p] of parent) {
    const from = placed.get(k);
    const to = placed.get(p);
    if (from && to) edges.push({ from, to, infected: infectedSet.has(`${k}>${p}`) });
  }
  edges.sort((a, b) => Number(a.infected) - Number(b.infected));

  // labels: root, direct deps, flagged; per-column collision culling
  const labelCols = new Map<number, Placed[]>();
  for (const pl of placed.values()) {
    const n = pl.node;
    if (n.depth === 0 || n.direct || n.depth === 1 || n.risk) {
      const list = labelCols.get(n.depth) ?? [];
      list.push(pl);
      labelCols.set(n.depth, list);
    }
  }
  const prio = (pl: Placed) => (pl.node.depth === 0 ? -1 : pl.node.risk ? RISK_RANK[pl.node.risk] : 5);
  const labels: Layout["labels"] = [];
  const maxChars = Math.floor((COL_W - 14) / 6.4);
  for (const list of labelCols.values()) {
    list.sort((a, b) => prio(a) - prio(b) || b.size - a.size);
    const kept: number[] = [];
    for (const pl of list) {
      if (kept.some((ky) => Math.abs(ky - pl.y) < 16)) continue;
      kept.push(pl.y);
      const n = pl.node;
      const root = n.depth === 0;
      const text = root ? graph.rootName || n.name : n.risk ? `${n.name}@${n.version}` : n.name;
      labels.push({
        key: n.key,
        x: root ? pl.x + 8 : pl.x,
        y: pl.y - 9,
        text: truncate(text, root ? 30 : maxChars),
        anchor: root ? "end" : "middle",
        risk: n.risk,
        root,
      });
    }
  }

  return {
    placed,
    width: PAD_L + maxDepth * COL_W + PAD_R + 10,
    height: maxY - minY + PAD_Y * 2,
    edges,
    labels,
  };
}

function edgePath(a: Placed, b: Placed): string {
  const mx = (a.x + b.x) / 2;
  return `M${a.x},${a.y} C${mx},${a.y} ${mx},${b.y} ${b.x},${b.y}`;
}

export interface GraphProps {
  graph: DependencyGraph;
  poisoned: Set<string>;
  poisonedAll: Set<string>;
  highlight: string | null;
  onSelect: (versionKey: string) => void;
  skipTo: () => void;
}

export default function Graph({ graph, poisoned, poisonedAll, highlight, onSelect, skipTo }: GraphProps) {
  const infectedSet = useMemo(() => new Set(graph.infected.map((e) => `${e.from}>${e.to}`)), [graph]);

  const parentOf = useMemo(() => {
    const m = new Map<string, string>();
    for (const e of graph.edges) if (!m.has(e.from)) m.set(e.from, e.to);
    return m;
  }, [graph]);

  const infectedKeep = useMemo(() => {
    const keep = new Set<string>([graph.root]);
    for (const e of graph.infected) {
      keep.add(e.from);
      keep.add(e.to);
    }
    const climb = (k: string) => {
      let cur: string | undefined = k;
      let guard = 0;
      while (cur && !keep.has(cur) && guard++ < 200) {
        keep.add(cur);
        cur = parentOf.get(cur);
      }
    };
    for (const n of graph.nodes) if (n.risk === "malware" || n.risk === "suspicious") climb(n.key);
    for (const k of poisonedAll) climb(k);
    return keep;
  }, [graph, parentOf, poisonedAll]);

  const hasInfected = infectedKeep.size > 1;
  const [onlyInfected, setOnlyInfected] = useState(() => {
    const narrow = typeof window !== "undefined" && window.innerWidth < 600;
    return (graph.nodes.length > 500 || narrow) && hasInfected;
  });

  const layout = useMemo(
    () => computeLayout(graph, onlyInfected ? infectedKeep : null, infectedSet),
    [graph, onlyInfected, infectedKeep, infectedSet],
  );

  const scrollRef = useRef<HTMLDivElement>(null);
  const wrapRef = useRef<HTMLDivElement>(null);
  const didScroll = useRef(false);
  const [tip, setTip] = useState<{ x: number; y: number; node: GraphNode } | null>(null);

  useLayoutEffect(() => {
    const el = scrollRef.current;
    if (!el || didScroll.current) return;
    didScroll.current = true;
    const mobile = window.innerWidth < 600;
    const root = layout.placed.get(graph.root);
    const firstInfected = [...layout.placed.values()]
      .filter((p) => p.node.risk === "malware" || p.node.risk === "suspicious")
      .sort((a, b) => RISK_RANK[a.node.risk!] - RISK_RANK[b.node.risk!])[0];
    const target = mobile && firstInfected ? firstInfected : root;
    if (!target) return;
    if (mobile && firstInfected) el.scrollLeft = Math.max(0, target.x - el.clientWidth / 2);
    else el.scrollLeft = el.scrollWidth;
    el.scrollTop = Math.max(0, target.y - el.clientHeight / 2);
  }, [layout, graph.root]);

  // scroll the highlighted node into view inside the graph box
  useEffect(() => {
    if (!highlight) return;
    const el = scrollRef.current;
    const p = layout.placed.get(highlight);
    if (!el || !p) return;
    const left = p.x - el.clientWidth / 2;
    const top = p.y - el.clientHeight / 2;
    el.scrollTo({ left: Math.max(0, left), top: Math.max(0, top) });
  }, [highlight, layout]);

  const flagged = useMemo(
    () =>
      graph.nodes
        .filter((n) => n.risk)
        .sort((a, b) => RISK_RANK[a.risk!] - RISK_RANK[b.risk!] || a.depth - b.depth || a.name.localeCompare(b.name))
        .slice(0, 8),
    [graph],
  );
  const flaggedTotal = useMemo(() => graph.nodes.filter((n) => n.risk).length, [graph]);

  const nodeFromEvent = (e: React.MouseEvent): GraphNode | null => {
    const g = (e.target as Element).closest("[data-key]");
    const key = g?.getAttribute("data-key");
    return key ? (layout.placed.get(key)?.node ?? null) : null;
  };

  const onMove = (e: React.MouseEvent) => {
    const n = nodeFromEvent(e);
    const wrap = wrapRef.current;
    if (!n || !wrap) {
      if (tip) setTip(null);
      return;
    }
    const r = wrap.getBoundingClientRect();
    setTip({ x: e.clientX - r.left, y: e.clientY - r.top, node: n });
  };

  const onClick = (e: React.MouseEvent) => {
    const n = nodeFromEvent(e);
    if (n && n.risk) onSelect(n.key);
  };

  const total = graph.nodes.length;
  const shown = layout.placed.size;
  const ariaLabel = `Dependency graph for ${graph.rootName}: ${shown} of ${total} packages shown, ${flaggedTotal} flagged. Use the flagged package buttons below to inspect findings.`;

  return (
    <div className="graph">
      <div className="graph-controls">
        <label className="check">
          <input
            type="checkbox"
            checked={onlyInfected}
            disabled={!hasInfected}
            onChange={(e) => {
              setOnlyInfected(e.target.checked);
              didScroll.current = false;
            }}
          />
          Show only infected paths
        </label>
        <span className="muted small">
          {hasInfected ? `Showing ${shown} of ${total} packages` : `${total} packages, no infected paths`}
        </span>
        <a
          className="skip-graph"
          href="#/"
          onClick={(e) => {
            e.preventDefault();
            skipTo();
          }}
        >
          Skip graph
        </a>
      </div>
      <ul className="legend" aria-label="Legend">
        <li>
          <svg width="14" height="14" aria-hidden="true">
            <circle cx="7" cy="7" r="5" className="n-malware" />
          </svg>
          Malware
        </li>
        <li>
          <svg width="14" height="14" aria-hidden="true">
            <circle cx="7" cy="7" r="4.5" className="n-suspicious" />
          </svg>
          Suspicious
        </li>
        <li>
          <svg width="14" height="14" aria-hidden="true">
            <circle cx="7" cy="7" r="4.5" className="n-vuln" />
          </svg>
          Known vulnerability
        </li>
        <li>
          <svg width="22" height="14" aria-hidden="true">
            <path d="M1 7h20" className="e-infected" style={{ strokeWidth: 3 }} />
          </svg>
          Infected path
        </li>
        {poisonedAll.size > 0 && (
          <li>
            <svg width="14" height="14" aria-hidden="true">
              <circle cx="7" cy="7" r="5" className="n-poisoned" />
            </svg>
            Poisoned in simulation
          </li>
        )}
      </ul>
      <div className="graph-wrap" ref={wrapRef}>
        <div className="graph-scroll" ref={scrollRef} tabIndex={0} role="region" aria-label="Dependency graph, scrollable">
          <svg
            role="group"
            aria-label={ariaLabel}
            width={layout.width}
            height={Math.max(layout.height, 120)}
            viewBox={`0 0 ${layout.width} ${Math.max(layout.height, 120)}`}
            onMouseMove={onMove}
            onMouseLeave={() => setTip(null)}
            onClick={onClick}
          >
            <g aria-hidden="true">
              {layout.edges.map(({ from, to, infected }) => {
                const w = Math.min(8, 1 + Math.log2(from.size) * 0.9);
                const poisonedEdge = poisoned.has(from.node.key);
                return (
                  <path
                    key={from.node.key}
                    d={edgePath(from, to)}
                    className={infected ? "e-infected" : poisonedEdge ? "e-poisoned" : from.node.dev ? "e-dev" : "e"}
                    style={{ strokeWidth: infected ? w + 1.6 : w }}
                  />
                );
              })}
            </g>
            <g aria-hidden="true">
              {[...layout.placed.values()].map((p) => {
                const n = p.node;
                const root = n.depth === 0;
                const isPoisoned = poisoned.has(n.key);
                const cls = root
                  ? "n-root"
                  : isPoisoned
                    ? "n-poisoned"
                    : n.risk === "malware"
                      ? "n-malware"
                      : n.risk === "suspicious"
                        ? "n-suspicious"
                        : n.risk === "vuln"
                          ? "n-vuln"
                          : "n";
                const r = root ? 7 : n.risk || isPoisoned ? 5 : n.direct ? 3.2 : 2.4;
                return (
                  <g key={n.key} data-key={n.key} className={n.risk ? "node flagged" : "node"}>
                    {highlight === n.key && <circle cx={p.x} cy={p.y} r={11} className="n-highlight" />}
                    {n.risk && <circle cx={p.x} cy={p.y} r={10} className="hit" />}
                    {!n.risk && !root && <circle cx={p.x} cy={p.y} r={6} className="hit" />}
                    <circle cx={p.x} cy={p.y} r={r} className={cls} />
                  </g>
                );
              })}
            </g>
            <g aria-hidden="true" className="labels">
              {layout.labels.map((l) => (
                <text
                  key={l.key}
                  x={l.x}
                  y={l.y}
                  textAnchor={l.anchor}
                  className={l.root ? "lbl lbl-root" : l.risk === "malware" || l.risk === "suspicious" ? "lbl lbl-flag" : "lbl"}
                >
                  {l.text}
                </text>
              ))}
            </g>
          </svg>
        </div>
        {tip && (
          <div className="graph-tip" style={{ left: tip.x + 14, top: tip.y + 14 }} aria-hidden="true">
            <code>
              {tip.node.depth === 0 ? graph.rootName : `${tip.node.name}@${tip.node.version}`}
            </code>
            <span>
              {poisoned.has(tip.node.key)
                ? "Poisoned in simulation"
                : tip.node.risk
                  ? RISK_LABEL[tip.node.risk]
                  : tip.node.depth === 0
                    ? "Your project"
                    : "No known risk"}
              {tip.node.dev ? " · dev dependency" : ""}
            </span>
          </div>
        )}
      </div>
      {flagged.length > 0 && (
        <div className="flagged-row">
          <span className="flagged-label" id="flagged-label">
            Flagged packages:
          </span>
          <ul aria-labelledby="flagged-label">
            {flagged.map((n) => (
              <li key={n.key}>
                <button type="button" className={`chip chip-${n.risk}`} onClick={() => onSelect(n.key)}>
                  <code>
                    {n.name}@{n.version}
                  </code>
                  <span className="visually-hidden"> ({RISK_LABEL[n.risk!]})</span>
                </button>
              </li>
            ))}
          </ul>
          {flaggedTotal > flagged.length && <span className="muted small">and {flaggedTotal - flagged.length} more below</span>}
        </div>
      )}
    </div>
  );
}
