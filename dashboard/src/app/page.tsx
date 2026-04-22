import Link from "next/link";
import { overviewStats, recentFindings } from "@/lib/queries";
import { StatCard } from "@/components/StatCard";
import { FindingRow } from "@/components/FindingRow";
import { ClearDataButton } from "@/components/ClearDataButton";
import { demoRowCount } from "@/lib/db";

export const dynamic = "force-dynamic";

export default async function HomePage() {
  const stats = overviewStats();
  const findings = recentFindings(10);
  const demoCount = demoRowCount();

  return (
    <main className="space-y-10">
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
