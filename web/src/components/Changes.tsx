import { useEffect, useState } from "react";
import type { ScanChanges } from "@api/types";
import { api, formatWhen, isoTime, signalLabel } from "../api";

/** What the latest scan changed compared with the previous one. Renders nothing until a project has two scans. */
export default function Changes({ projectId, scanId }: { projectId: string; scanId: string }) {
  const [d, setD] = useState<ScanChanges | null>(null);
  useEffect(() => {
    let live = true;
    api.changes(projectId).then((x) => live && setD(x), () => live && setD(null));
    return () => {
      live = false;
    };
  }, [projectId, scanId]);
  if (!d || d.since === null) return null;
  const total = d.added.length + d.removed.length + d.changed.length;
  return (
    <section className={`changes${d.newlyFlagged.length ? " changes-hot" : ""}`} aria-labelledby="changes-h">
      <h2 id="changes-h" className="changes-title">
        Since the last scan <time dateTime={isoTime(d.since)}>{formatWhen(d.since)}</time>
      </h2>
      {total === 0 ? (
        <p className="muted">No dependency changed.</p>
      ) : (
        <p>
          {[
            d.changed.length && `${d.changed.length} version ${d.changed.length === 1 ? "change" : "changes"}`,
            d.added.length && `${d.added.length} new ${d.added.length === 1 ? "package" : "packages"}`,
            d.removed.length && `${d.removed.length} removed`,
          ]
            .filter(Boolean)
            .join(" · ")}
          {d.newlyFlagged.length > 0 ? (
            <>
              {" "}
              · <strong>{d.newlyFlagged.length} of the new versions {d.newlyFlagged.length === 1 ? "is" : "are"} flagged</strong>
            </>
          ) : (
            " · none of the new versions is flagged"
          )}
        </p>
      )}
      {d.newlyFlagged.length > 0 && (
        <ul className="changes-flagged">
          {d.newlyFlagged.slice(0, 8).map((f) => (
            <li key={f.findingId}>
              <code>
                {f.name}@{f.version}
              </code>{" "}
              {signalLabel(f.signal)}
            </li>
          ))}
        </ul>
      )}
      {total > 0 && (
        <details>
          <summary>Show every change</summary>
          <ul className="changes-list">
            {d.changed.map((c) => (
              <li key={`c-${c.name}`}>
                <code>{c.name}</code> {c.from.join(", ") || "–"} → {c.to.join(", ") || "–"}
              </li>
            ))}
            {d.added.map((a) => (
              <li key={`a-${a.name}@${a.version}`}>
                <code>
                  {a.name}@{a.version}
                </code>{" "}
                added
              </li>
            ))}
            {d.removed.map((r) => (
              <li key={`r-${r.name}@${r.version}`}>
                <code>
                  {r.name}@{r.version}
                </code>{" "}
                removed
              </li>
            ))}
          </ul>
        </details>
      )}
    </section>
  );
}
