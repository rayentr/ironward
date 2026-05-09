import Link from "next/link";
import { activityTrends, overviewStats, recentFindings } from "@/lib/queries";
import { StatCard } from "@/components/StatCard";
import { ActivityTrends } from "@/components/ActivityTrends";
import { FindingRow } from "@/components/FindingRow";
import { ClearDataButton } from "@/components/ClearDataButton";
import { demoRowCount } from "@/lib/db";

export const dynamic = "force-dynamic";

export default async function HomePage() {
  const stats = overviewStats();
  const findings = recentFindings(10);
  const trends = activityTrends(7);
  const demoCount = demoRowCount();

  const healthColor = stats.critical > 0 ? "text-[var(--color-danger)]" : stats.high > 0 ? "text-[var(--color-warn)]" : "text-[var(--color-accent)]";
  const healthLabel = stats.critical > 0 ? "Critical" : stats.high > 0 ? "At Risk" : stats.totalScans > 0 ? "Secure" : "No Data";

  return (
    <main className="space-y-10">
      <section className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-xl p-6 flex items-center justify-between shadow-sm">
        <div>
          <h2 className="text-sm font-medium text-[var(--color-muted)] uppercase tracking-wider">System Security Health</h2>
          <div className={`text-4xl font-bold mt-1 ${healthColor}`}>
            {healthLabel}
          </div>
        </div>
        <div className="text-right">
          <div className="text-sm text-[var(--color-muted)] mb-1">Critical Issues</div>
          <div className={`text-2xl font-mono ${stats.critical > 0 ? 'text-[var(--color-danger)]' : 'text-[var(--color-muted)]'}`}>
            {stats.critical}
          </div>
        </div>
      </section>

      <section className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div className="md:col-span-2">
           <ActivityTrends trends={trends} />
        </div>
        <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-xl p-6 flex flex-col justify-center">
            <div className="text-sm font-medium text-[var(--color-muted)] uppercase tracking-wider mb-2">Total Insights</div>
            <div className="text-3xl font-bold">{stats.totalFindings}</div>
            <div className="text-xs text-[var(--color-muted)] mt-2">Security findings detected across all targets.</div>
        </div>
      </section>

      <section className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Overview</h1>
          <p className="text-[var(--color-muted)] mt-1">
            Local view of every scan the Ironward CLI or MCP server has recorded on this machine.
            {demoCount > 0 && (
              <span className="ml-2 inline-block rounded-full bg-yellow-500/15 text-yellow-300 px-2 py-0.5 text-[11px]">
                {demoCount} demo scan{demoCount === 1 ? "" : "s"} active
              </span>
            )}
          </p>
        </div>
        <ClearDataButton demoCount={demoCount} totalCount={stats.totalScans} />
      </section>

      <section className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <StatCard label="Total scans" value={stats.totalScans} />
        <StatCard label="Vulns found" value={stats.totalFindings} />
        <StatCard label="Critical" value={stats.critical} accent={stats.critical ? "danger" : "text"} />
        <StatCard label="Fixed" value={stats.fixed} accent={stats.fixed ? "accent" : "text"} />
      </section>

      <section className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <StatCard label="High" value={stats.high} accent={stats.high ? "warn" : "text"} />
        <StatCard label="Medium" value={stats.medium} />
        <StatCard label="Low" value={stats.low} />
        <StatCard label="Open" value={stats.open} />
      </section>

      <section>
        <div className="flex items-baseline justify-between mb-3">
          <h2 className="text-lg font-semibold">Recent findings</h2>
          <Link href="/findings" className="text-sm text-[var(--color-muted)] hover:text-white">
            See all →
          </Link>
        </div>
        {findings.length === 0 ? (
          <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-6 text-sm text-[var(--color-muted)]">
            No findings yet. Run <code className="font-mono">npx ironward scan-secrets src/ --record</code> to populate.
          </div>
        ) : (
          <div className="space-y-2">
            {findings.map((f) => <FindingRow key={f.id} finding={f} />)}
          </div>
        )}
      </section>
    </main>
  );
}
