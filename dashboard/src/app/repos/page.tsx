import { repoSummaries } from "@/lib/queries";

export const dynamic = "force-dynamic";

function scoreColor(score: number): string {
  if (score >= 85) return "text-[var(--color-accent)]";
  if (score >= 60) return "text-[var(--color-warn)]";
  return "text-[var(--color-danger)]";
}

function bar(pct: number, color: string): string {
  return `bg-gradient-to-r ${color}`;
}
void bar;

export default async function ReposPage() {
  const repos = repoSummaries();
  return (
    <main className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Repos</h1>
        <p className="text-[var(--color-muted)] mt-1">
          Scanned repositories, ranked by current security score.
        </p>
      </div>

      {repos.length === 0 ? (
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-6 text-sm text-[var(--color-muted)]">
          No scans recorded yet. Pass <code className="font-mono">--record --repo owner/name</code> to a CLI scan to populate this view.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {repos.map((r) => (
            <div key={r.repo} className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
              <div className="flex items-baseline justify-between">
                <div className="font-semibold">{r.repo}</div>
                <div className={`text-xl font-semibold ${scoreColor(r.score)}`}>{r.score}</div>
              </div>
              <div className="mt-3 h-2 w-full rounded-full bg-[var(--color-surface-2)] overflow-hidden">
                <div
                  className={`h-2 rounded-full ${r.score >= 85 ? "bg-[var(--color-accent)]" : r.score >= 60 ? "bg-[var(--color-warn)]" : "bg-[var(--color-danger)]"}`}
                  style={{ width: `${r.score}%` }}
                />
              </div>
              <div className="mt-3 text-xs text-[var(--color-muted)]">
                {r.scansCount} scan{r.scansCount === 1 ? "" : "s"} · {r.openFindings} open
                {r.critical ? ` · ${r.critical} critical` : ""}
                {r.high ? ` · ${r.high} high` : ""}
              </div>
            </div>
          ))}
        </div>
      )}
    </main>
  );
}
