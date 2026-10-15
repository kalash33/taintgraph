import { useMemo } from "react";
import type { Evidence } from "@api/types";
import { nodeKind, shortKey, truncate } from "../api";

export type FlagMap = Map<string, "malware" | "suspicious" | "vuln">;

const COL = 170;
const ROW = 54;
const PAD_X = 80;
const PAD_Y = 40;

export function mergeEvidence(list: (Evidence | undefined)[]): Evidence {
  const nodes = new Set<string>();
  const edges = new Map<string, [string, string, string]>();
  for (const ev of list) {
    if (!ev) continue;
    for (const n of ev.nodes ?? []) nodes.add(n);
    for (const e of ev.edges ?? []) {
      nodes.add(e[0]);
      nodes.add(e[1]);
      edges.set(`${e[0]}|${e[1]}|${e[2]}`, e);
    }
  }
  return { nodes: [...nodes], edges: [...edges.values()] };
}

export default function EvidenceGraph({ evidence, projectName, flags }: { evidence: Evidence; projectName: string; flags: FlagMap }) {
  const layout = useMemo(() => {
    const nodes = evidence.nodes;
    const adj = new Map<string, Set<string>>();
    for (const n of nodes) adj.set(n, new Set());
    for (const [a, b] of evidence.edges) {
      adj.get(a)?.add(b);
      adj.get(b)?.add(a);
    }
    const start = nodes.find((n) => n.startsWith("project/")) ?? nodes[0];
    const level = new Map<string, number>();
    if (start) {
      level.set(start, 0);
      const queue = [start];
      while (queue.length) {
        const cur = queue.shift()!;
        for (const nb of adj.get(cur) ?? []) {
          if (!level.has(nb)) {
            level.set(nb, level.get(cur)! + 1);
            queue.push(nb);
          }
        }
      }
    }
    let maxL = Math.max(0, ...level.values());
    // disconnected nodes go in a trailing column
    const orphans = nodes.filter((n) => !level.has(n));
    if (orphans.length) {
      maxL += 1;
      for (const o of orphans) level.set(o, maxL);
    }
    const cols: string[][] = Array.from({ length: maxL + 1 }, () => []);
    for (const n of nodes) cols[level.get(n)!].push(n);
    const pos = new Map<string, { x: number; y: number }>();
    cols.forEach((col, l) => {
      if (l > 0) {
        const bary = (n: string) => {
          const ys = [...(adj.get(n) ?? [])].map((m) => pos.get(m)?.y).filter((y): y is number => y !== undefined);
          return ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : Infinity;
        };
        col.sort((a, b) => bary(a) - bary(b) || a.localeCompare(b));
      }
      col.forEach((n, i) => pos.set(n, { x: PAD_X + l * COL, y: PAD_Y + i * ROW }));
    });
    const tallest = Math.max(1, ...cols.map((c) => c.length));
    // center shorter columns vertically
    cols.forEach((col) => {
      const offset = ((tallest - col.length) * ROW) / 2;
      for (const n of col) pos.get(n)!.y += offset;
    });
    return { pos, width: PAD_X * 2 + maxL * COL, height: PAD_Y + tallest * ROW, cols };
  }, [evidence]);

  if (!evidence.nodes.length) return <p className="muted small">No graph evidence for this answer yet.</p>;

  const flaggedCount = evidence.nodes.filter((n) => flags.has(n)).length;
  const label = `Evidence graph: ${evidence.nodes.length} nodes and ${evidence.edges.length} connections${flaggedCount ? `, ${flaggedCount} flagged` : ""}. Scroll to see all of it.`;

  return (
    <div className="evidence-scroll" tabIndex={0} role="region" aria-label={label}>
      <svg width={layout.width} height={layout.height} viewBox={`0 0 ${layout.width} ${layout.height}`} aria-hidden="true">
        <g>
          {evidence.edges.map(([a, b, rel]) => {
            const p = layout.pos.get(a);
            const q = layout.pos.get(b);
            if (!p || !q) return null;
            const mx = (p.x + q.x) / 2;
            const hot = flags.get(a) === "malware" || flags.get(b) === "malware" || flags.get(a) === "suspicious" || flags.get(b) === "suspicious";
            return (
              <path key={`${a}|${b}|${rel}`} d={`M${p.x},${p.y} C${mx},${p.y} ${mx},${q.y} ${q.x},${q.y}`} className={hot ? "ev-edge hot" : "ev-edge"}>
                <title>{rel}</title>
              </path>
            );
          })}
        </g>
        <g>
          {evidence.nodes.map((n) => {
            const p = layout.pos.get(n)!;
            const kind = nodeKind(n);
            const flag = flags.get(n);
            const cls = flag ? `ev-node ev-${flag}` : `ev-node ev-${kind}`;
            return (
              <g key={n}>
                {kind === "account" ? (
                  <rect x={p.x - 5} y={p.y - 5} width={10} height={10} rx={2} className={cls} />
                ) : kind === "advisory" ? (
                  <rect x={p.x - 5} y={p.y - 5} width={10} height={10} className={cls} transform={`rotate(45 ${p.x} ${p.y})`} />
                ) : (
                  <circle cx={p.x} cy={p.y} r={kind === "project" ? 7 : 5.5} className={cls} />
                )}
                <text x={p.x} y={p.y - 11} textAnchor="middle" className={flag === "malware" || flag === "suspicious" ? "lbl lbl-flag" : "lbl"}>
                  {truncate(shortKey(n, projectName), 24)}
                </text>
              </g>
            );
          })}
        </g>
      </svg>
    </div>
  );
}
