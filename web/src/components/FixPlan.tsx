import { useEffect, useState } from "react";
import type { FixItem, FixPlan as Plan } from "@api/types";
import { api, signalLabel } from "../api";
import { ErrorState, Loading } from "./States";

type Tab = "npm" | "pnpm" | "yarn" | "python";

function change(i: FixItem) {
  if (i.to) return { text: `${i.from} → ${i.to}`, kind: i.action === "pin_previous" ? "Back to the previous release" : "Upgrade" };
  return i.action === "no_fix" ? { text: i.from, kind: "No fix released yet" } : { text: i.from, kind: "Remove" };
}

function snippet(plan: Plan, tab: Tab): string {
  if (tab === "python" && plan.python) return `# constraints.txt\n${plan.python.constraints}\n# then\n${plan.python.commands.join("\n")}`;
  if (!plan.npm) return "";
  const cmds = plan.npm.commands.length ? `\n\n# commands\n${plan.npm.commands.join("\n")}` : "";
  if (tab === "pnpm") return `// package.json\n${JSON.stringify({ pnpm: { overrides: plan.npm.pnpmOverrides } }, null, 2)}${cmds.replace(/npm install/g, "pnpm add").replace(/npm uninstall/g, "pnpm remove").replace("run: pnpm add", "run: pnpm install")}`;
  if (tab === "yarn") return `// package.json\n${JSON.stringify({ resolutions: plan.npm.resolutions }, null, 2)}${cmds.replace(/npm install( --save-dev)?/g, (_, dev) => `yarn add${dev ? " --dev" : ""}`).replace(/npm uninstall/g, "yarn remove").replace("run: yarn add", "run: yarn install")}`;
  return `// package.json\n${JSON.stringify({ overrides: plan.npm.overrides }, null, 2)}${cmds}`;
}

export default function FixPlan({ projectId, refreshKey }: { projectId: string; refreshKey: string }) {
  const [plan, setPlan] = useState<Plan | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [tab, setTab] = useState<Tab>("npm");
  const [copied, setCopied] = useState(false);
  const [all, setAll] = useState(false);

  const load = () => {
    setError(null);
    api.fix(projectId).then((p) => {
      setPlan(p);
      setTab((t) => (t === "python" && !p.python ? "npm" : !p.npm && p.python ? "python" : t));
    }, setError);
  };
  useEffect(load, [projectId, refreshKey]);

  if (error) return <ErrorState error={error} onRetry={load} />;
  if (!plan) return <Loading label="Planning the fix" />;
  if (!plan.items.length)
    return (
      <p className="muted">
        Nothing needs changing right now{plan.skipped ? `; ${plan.skipped} lower-severity ${plan.skipped === 1 ? "finding is" : "findings are"} left out of the plan` : ""}.
      </p>
    );

  const tabs: { id: Tab; label: string }[] = [
    ...(plan.npm ? ([{ id: "npm", label: "npm" }, { id: "pnpm", label: "pnpm" }, { id: "yarn", label: "yarn" }] as const) : []),
    ...(plan.python ? ([{ id: "python", label: "Python (uv / pip)" }] as const) : []),
  ];
  const code = snippet(plan, tab);
  // Compromises and tampering always show; ordinary CVEs collapse after the first five.
  const urgent = plan.items.filter((i) => i.why !== "vulnerability");
  const cves = plan.items.filter((i) => i.why === "vulnerability");
  const shown = all ? plan.items : [...urgent, ...cves.slice(0, 5)];
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked: the text is selectable */
    }
  };

  return (
    <div className="fix-plan">
      <p className="lede-small">
        {plan.items.length} {plan.items.length === 1 ? "change" : "changes"}. Every target version was re-checked against OSV.dev, so the plan never moves you to
        another flagged release.{plan.skipped ? ` ${plan.skipped} lower-severity ${plan.skipped === 1 ? "finding is" : "findings are"} left out.` : ""}
      </p>

      {plan.incident.length > 0 && (
        <div className="fix-incident" role="note">
          <strong>Compromised versions were installed.</strong> Upgrading isn't enough:
          <ul>
            {plan.incident.map((s) => (
              <li key={s}>{s}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="table-scroll" tabIndex={0} role="region" aria-label="Fix plan, scrollable">
        <table>
          <thead>
            <tr>
              <th scope="col">Package</th>
              <th scope="col">Change</th>
              <th scope="col">Why</th>
              <th scope="col">Notes</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((i) => {
              const c = change(i);
              return (
                <tr key={`${i.name}@${i.from}`}>
                  <td>
                    <code>{i.name}</code>
                    <div className="muted small">{i.direct ? "your dependency" : i.ecosystem === "PyPI" ? "transitive: constraint" : "transitive: override"}{i.dev ? ", dev" : ""}</div>
                  </td>
                  <td>
                    <code>{c.text}</code>
                    <div className="small">
                      {c.kind}
                      {i.majorChange && <span className="pill pill-suspicious fix-pill">major version</span>}
                    </div>
                  </td>
                  <td>
                    <span className={`pill ${["malware", "possible_malware", "removed"].includes(i.why) ? "pill-compromised" : i.why === "vulnerability" ? "pill-vulnerable" : "pill-suspicious"}`}>{signalLabel(i.why)}</span>
                  </td>
                  <td className="small">
                    {i.note}
                    {i.check === "clean" && <span className="fix-check"> Re-checked: no advisories.</span>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {!all && shown.length < plan.items.length && (
        <button type="button" className="btn-link" onClick={() => setAll(true)}>
          Show all {plan.items.length} changes
        </button>
      )}

      {tabs.length > 0 && (
        <div className="fix-snippets">
          <div className="fix-tabs" role="tablist" aria-label="Package manager">
            {tabs.map((t) => (
              <button key={t.id} type="button" role="tab" aria-selected={tab === t.id} className={tab === t.id ? "fix-tab is-active" : "fix-tab"} onClick={() => setTab(t.id)}>
                {t.label}
              </button>
            ))}
            <button type="button" className="btn btn-small fix-copy" onClick={copy}>
              {copied ? "Copied" : "Copy"}
            </button>
          </div>
          <pre className="code-block" role="tabpanel">
            <code>{code}</code>
          </pre>
        </div>
      )}
    </div>
  );
}
