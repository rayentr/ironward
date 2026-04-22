export function StatCard({
  label,
  value,
  accent = "text",
}: {
  label: string;
  value: string | number;
  accent?: "text" | "accent" | "danger" | "warn";
}) {
  const color =
    accent === "accent"
      ? "text-[var(--color-accent)]"
      : accent === "danger"
        ? "text-[var(--color-danger)]"
        : accent === "warn"
          ? "text-[var(--color-warn)]"
          : "text-white";
  return (
    <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
      <div className={`text-3xl font-semibold tracking-tight ${color}`}>{value}</div>
      <div className="mt-1 text-sm text-[var(--color-muted)]">{label}</div>
    </div>
  );
}
