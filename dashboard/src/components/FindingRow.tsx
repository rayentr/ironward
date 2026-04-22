import type { FindingRow as FindingRowType } from "@/lib/queries";
import { SeverityPill } from "./SeverityPill";

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

export function FindingRow({ finding }: { finding: FindingRowType }) {
  const loc = finding.path ? `${finding.path}${finding.line !== null ? `:${finding.line}` : ""}` : "";
  return (
    <div className="flex items-start gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-3 hover:bg-[var(--color-surface-2)] transition-colors">
      <div className="pt-0.5"><SeverityPill severity={finding.severity} /></div>
      <div className="flex-1 min-w-0">
        <div className="text-sm font-medium truncate">{finding.title}</div>
        <div className="text-xs text-[var(--color-muted)] mt-0.5 truncate">
          {finding.tool} · {finding.repo ?? "—"}
          {loc && <span> · <span className="font-mono">{loc}</span></span>}
          <span> · {timeAgo(finding.lastSeenAt)}</span>
        </div>
      </div>
      <div className="flex items-center gap-2 text-xs">
        {finding.status === "fixed" && (
          <span className="rounded-full bg-emerald-500/15 text-emerald-300 px-2 py-0.5">fixed ✓</span>
        )}
        {finding.status === "open" && (
          <span className="rounded-full bg-neutral-700/40 text-neutral-300 px-2 py-0.5">open</span>
        )}
        {finding.status === "dismissed" && (
          <span className="rounded-full bg-neutral-700/40 text-neutral-500 px-2 py-0.5">dismissed</span>
        )}
        {finding.prUrl && (
          <a
            href={finding.prUrl}
            target="_blank"
            rel="noreferrer"
            className="rounded-full bg-[var(--color-accent)]/15 text-[var(--color-accent)] px-2 py-0.5 hover:bg-[var(--color-accent)]/25"
          >
            PR
          </a>
        )}
      </div>
    </div>
  );
}
