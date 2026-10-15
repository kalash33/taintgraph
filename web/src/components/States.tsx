import type { ReactNode } from "react";
import { ApiError, SERVER_DOWN } from "../api";

export function Loading({ label, compact = false }: { label: string; compact?: boolean }) {
  return (
    <div className={compact ? "state state-loading compact" : "state state-loading"} role="status">
      <span className="ripple" aria-hidden="true">
        <span />
        <span />
        <span />
      </span>
      <span>{label}</span>
    </div>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="state state-empty">
      <p className="state-title">{title}</p>
      {children}
    </div>
  );
}

export function ErrorState({
  error,
  onRetry,
  title,
}: {
  error: unknown;
  onRetry?: () => void;
  title?: string;
}) {
  const e = error instanceof ApiError ? error : null;
  const message = e?.message ?? (error instanceof Error ? error.message : String(error ?? ""));
  const down = e?.kind === "unreachable" || message === SERVER_DOWN;
  return (
    <div className="state state-error" role="alert">
      {title && <p className="state-title">{title}</p>}
      <p>{down ? SERVER_DOWN : message}</p>
      {down && import.meta.env.DEV && (
        <p className="muted small">
          If you're running Upstream locally, start it with <code>pnpm start</code>.
        </p>
      )}
      {onRetry && (
        <button type="button" className="btn" onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  );
}
