import { allFindings } from "@/lib/queries";
import { FindingRow } from "@/components/FindingRow";

export const dynamic = "force-dynamic";

interface SearchParams {
  severity?: string;
  status?: string;
}

export default async function FindingsPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const params = await searchParams;
  const filter: { severity?: string; status?: string } = {};
  if (params.severity) filter.severity = params.severity;
  if (params.status) filter.status = params.status;
  const findings = allFindings(filter);

  const sevOptions = ["critical", "high", "medium", "low"];
  const statusOptions = ["open", "fixed", "dismissed"];

  return (
    <main className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Findings</h1>
        <p className="text-[var(--color-muted)] mt-1">
          {findings.length} finding{findings.length === 1 ? "" : "s"}
          {filter.severity && ` · severity: ${filter.severity}`}
          {filter.status && ` · status: ${filter.status}`}
        </p>
      </div>

      <div className="flex flex-wrap gap-2 text-sm">
        <a
          href="/findings"
          className={`px-3 py-1 rounded-full border border-[var(--color-border)] ${
            !filter.severity && !filter.status ? "bg-white text-black" : "text-[var(--color-muted)] hover:text-white"
          }`}
        >
          All
        </a>
        {sevOptions.map((s) => (
          <a
            key={s}
            href={`/findings?severity=${s}`}
            className={`px-3 py-1 rounded-full border border-[var(--color-border)] ${
              filter.severity === s ? "bg-white text-black" : "text-[var(--color-muted)] hover:text-white"
            }`}
          >
            {s}
          </a>
        ))}
        <span className="w-px bg-[var(--color-border)] mx-1" />
        {statusOptions.map((s) => (
          <a
            key={s}
            href={`/findings?status=${s}`}
            className={`px-3 py-1 rounded-full border border-[var(--color-border)] ${
              filter.status === s ? "bg-white text-black" : "text-[var(--color-muted)] hover:text-white"
            }`}
          >
            {s}
          </a>
        ))}
      </div>

      {findings.length === 0 ? (
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-6 text-sm text-[var(--color-muted)]">
          Nothing matches this filter.
        </div>
      ) : (
        <div className="space-y-2">
          {findings.map((f) => <FindingRow key={f.id} finding={f} />)}
        </div>
      )}
    </main>
  );
}
