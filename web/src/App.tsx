import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { sessionGet, sessionSet } from "./api";
import Intake from "./components/Intake";
import Project from "./components/Project";
import Ask from "./components/Ask";
import Memory from "./components/Memory";
import HeaderStatus from "./components/HeaderStatus";

export type Route =
  | { name: "intake" }
  | { name: "project"; id: string }
  | { name: "ask"; id: string; investigationId?: string }
  | { name: "memory" }
  | { name: "missing" };

export function parseHash(hash: string): Route {
  const raw = hash.replace(/^#/, "") || "/";
  const [path, query = ""] = raw.split("?");
  const parts = path.split("/").filter(Boolean).map((p) => {
    try {
      return decodeURIComponent(p);
    } catch {
      return p;
    }
  });
  if (parts.length === 0) return { name: "intake" };
  if (parts[0] === "memory" && parts.length === 1) return { name: "memory" };
  if (parts[0] === "p" && parts[1]) {
    if (parts.length === 2) return { name: "project", id: parts[1] };
    if (parts.length === 3 && parts[2] === "ask") {
      const i = new URLSearchParams(query).get("i") ?? undefined;
      return { name: "ask", id: parts[1], investigationId: i || undefined };
    }
  }
  return { name: "missing" };
}

export const href = {
  intake: () => "#/",
  project: (id: string) => `#/p/${encodeURIComponent(id)}`,
  ask: (id: string, investigationId?: string) =>
    `#/p/${encodeURIComponent(id)}/ask${investigationId ? `?i=${encodeURIComponent(investigationId)}` : ""}`,
  memory: () => "#/memory",
};

export function navigate(to: string) {
  if (window.location.hash === to) return;
  window.location.hash = to;
}

/* ---------- hash subscription ---------- */

const subscribe = (cb: () => void) => {
  window.addEventListener("hashchange", cb);
  return () => window.removeEventListener("hashchange", cb);
};
const getHash = () => window.location.hash;

/* ---------- per-history-entry scroll restoration ---------- */

function entryKey(): string {
  const st = window.history.state as { taintgraphKey?: string } | null;
  if (st && typeof st.taintgraphKey === "string") return st.taintgraphKey;
  const key = Math.random().toString(36).slice(2, 10);
  try {
    window.history.replaceState({ ...(st ?? {}), taintgraphKey: key }, "");
  } catch {
    /* ignore */
  }
  return key;
}

function useScrollRestore(hash: string) {
  const keyRef = useRef<string>("");
  useEffect(() => {
    try {
      window.history.scrollRestoration = "manual";
    } catch {
      /* ignore */
    }
    let t = 0;
    const onScroll = () => {
      window.clearTimeout(t);
      t = window.setTimeout(() => {
        if (keyRef.current) sessionSet(`taintgraph-scroll:${keyRef.current}`, String(Math.round(window.scrollY)));
      }, 120);
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => {
      window.removeEventListener("scroll", onScroll);
      window.clearTimeout(t);
    };
  }, []);

  useEffect(() => {
    const key = entryKey();
    keyRef.current = key;
    const saved = Number(sessionGet(`taintgraph-scroll:${key}`));
    if (!saved) {
      window.scrollTo(0, 0);
      return;
    }
    // Content loads asynchronously: keep trying until the page is tall enough (max ~2.5 s).
    let tries = 0;
    let raf = 0;
    const attempt = () => {
      const max = document.documentElement.scrollHeight - window.innerHeight;
      if (max >= saved || tries > 150) {
        window.scrollTo(0, Math.min(saved, Math.max(0, max)));
        return;
      }
      tries++;
      raf = window.requestAnimationFrame(attempt);
    };
    attempt();
    return () => window.cancelAnimationFrame(raf);
  }, [hash]);
}

/* ---------- focus the page heading on route change ---------- */

function useFocusHeading(hash: string) {
  const first = useRef(true);
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    let tries = 0;
    let raf = 0;
    const attempt = () => {
      const h = document.getElementById("page-title");
      if (h) {
        h.focus({ preventScroll: true });
        return;
      }
      if (tries++ < 60) raf = window.requestAnimationFrame(attempt);
    };
    raf = window.requestAnimationFrame(attempt);
    // Pages swap their loading heading for the real one; if focus fell to <body>, follow it.
    const obs = new MutationObserver(() => {
      const active = document.activeElement;
      if (active && active !== document.body) return;
      document.getElementById("page-title")?.focus({ preventScroll: true });
    });
    const main = document.getElementById("main");
    if (main) obs.observe(main, { childList: true, subtree: true });
    const stop = window.setTimeout(() => obs.disconnect(), 5000);
    return () => {
      window.cancelAnimationFrame(raf);
      obs.disconnect();
      window.clearTimeout(stop);
    };
  }, [hash]);
}

/* ---------- theme ---------- */

type Theme = "system" | "light" | "dark";
const THEME_KEY = "taintgraph-theme";

function readTheme(): Theme {
  try {
    const v = window.localStorage.getItem(THEME_KEY);
    if (v === "light" || v === "dark") return v;
  } catch {
    /* ignore */
  }
  return "system";
}

function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(readTheme);
  useEffect(() => {
    const root = document.documentElement;
    if (theme === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", theme);
    try {
      if (theme === "system") window.localStorage.removeItem(THEME_KEY);
      else window.localStorage.setItem(THEME_KEY, theme);
    } catch {
      /* ignore */
    }
  }, [theme]);
  const next: Theme = theme === "system" ? "light" : theme === "light" ? "dark" : "system";
  const label = theme === "system" ? "Theme: system" : theme === "light" ? "Theme: light" : "Theme: dark";
  return (
    <button type="button" className="btn-quiet theme-toggle" onClick={() => setTheme(next)} aria-label={`${label}. Switch to ${next}.`}>
      <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true" focusable="false">
        {theme === "dark" ? (
          <path fill="currentColor" d="M6.2 1.1a.6.6 0 0 1 .2.7 5.5 5.5 0 0 0 7.8 7.8.6.6 0 0 1 .8.8A7 7 0 1 1 5.5.9a.6.6 0 0 1 .7.2Z" />
        ) : theme === "light" ? (
          <g fill="currentColor">
            <circle cx="8" cy="8" r="3.2" />
            <path d="M8 0.8v2M8 13.2v2M0.8 8h2M13.2 8h2M2.9 2.9l1.4 1.4M11.7 11.7l1.4 1.4M2.9 13.1l1.4-1.4M11.7 4.3l1.4-1.4" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
          </g>
        ) : (
          <path fill="currentColor" d="M8 1a7 7 0 1 0 0 14A7 7 0 0 0 8 1Zm0 1.5v11a5.5 5.5 0 0 1 0-11Z" />
        )}
      </svg>
      {theme === "system" ? "Auto" : theme === "light" ? "Light" : "Dark"}
    </button>
  );
}

/* ---------- app ---------- */

function skipToMain(e: React.MouseEvent<HTMLAnchorElement>) {
  e.preventDefault();
  const main = document.getElementById("main");
  if (main) {
    main.focus();
    main.scrollIntoView();
  }
}

export default function App() {
  const hash = useSyncExternalStore(subscribe, getHash, getHash);
  const route = parseHash(hash);
  useScrollRestore(hash);
  useFocusHeading(hash);

  const projectId = route.name === "project" || route.name === "ask" ? route.id : null;

  return (
    <>
      <a className="skip-link" href="#main" onClick={skipToMain}>
        Skip to content
      </a>
      <header className="site-header">
        <nav className="nav" aria-label="Main">
          <a className="wordmark" href={href.intake()}>
            <svg viewBox="0 0 32 22" width="30" height="21" aria-hidden="true" focusable="false">
              <path d="M5 11 15 4.5 27 11M5 11l10 6.5" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
              <path d="M15 17.5 27 11" fill="none" stroke="var(--taint)" strokeWidth="2.4" strokeLinecap="round" />
              <circle cx="5" cy="11" r="3" fill="currentColor" />
              <circle cx="15" cy="4.5" r="3" fill="currentColor" />
              <circle cx="15" cy="17.5" r="3.2" fill="var(--taint)" />
              <circle cx="27" cy="11" r="3.6" fill="currentColor" />
            </svg>
            Taintgraph
          </a>
          <ul className="nav-links">
            {projectId && (
              <>
                <li>
                  <a href={href.project(projectId)} aria-current={route.name === "project" ? "page" : undefined}>
                    Overview
                  </a>
                </li>
                <li>
                  <a href={href.ask(projectId)} aria-current={route.name === "ask" ? "page" : undefined}>
                    Ask
                  </a>
                </li>
              </>
            )}
            <li>
              <a href={href.intake()} aria-current={route.name === "intake" ? "page" : undefined}>
                Scan
              </a>
            </li>
            <li>
              <a href={href.memory()} aria-current={route.name === "memory" ? "page" : undefined}>
                Memory
              </a>
            </li>
          </ul>
          <HeaderStatus />
          <ThemeToggle />
        </nav>
      </header>
      <main id="main" tabIndex={-1}>
        {route.name === "intake" && <Intake />}
        {route.name === "project" && <Project key={route.id} id={route.id} />}
        {route.name === "ask" && <Ask key={`${route.id}:${route.investigationId ?? ""}`} id={route.id} investigationId={route.investigationId} />}
        {route.name === "memory" && <Memory />}
        {route.name === "missing" && (
          <div className="page narrow">
            <h1 id="page-title" tabIndex={-1}>
              This page doesn't exist
            </h1>
            <p>
              <a href={href.intake()}>Go back to Scan</a> to start an investigation.
            </p>
          </div>
        )}
      </main>
      <footer className="site-footer">
        <div className="footer-inner">
          <div>
            <p className="footer-brand">Taintgraph</p>
            <p>See how a supply-chain attack reaches your app, and who could poison it next.</p>
            <p className="footer-small">Data from OSV.dev, npm, PyPI, deps.dev and ecosyste.ms. Graph stored in FalkorDB. Built for Graph Hacks 2026.</p>
          </div>
          <ul className="footer-links">
            <li>
              <a href="https://github.com/kalash33/taintgraph" target="_blank" rel="noreferrer">Source code</a>
            </li>
            <li>
              <a href="https://github.com/kalash33/taintgraph/blob/main/docs/graph-model.md" target="_blank" rel="noreferrer">Graph model</a>
            </li>
            <li>
              <a href="https://github.com/kalash33/taintgraph/blob/main/docs/agents.md" target="_blank" rel="noreferrer">How the agents work</a>
            </li>
            <li>
              <a href="https://github.com/kalash33/taintgraph/blob/main/benchmark/RESULTS.md" target="_blank" rel="noreferrer">Benchmark: 19/19 real attacks</a>
            </li>
          </ul>
        </div>
      </footer>
    </>
  );
}
