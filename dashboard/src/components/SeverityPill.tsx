const BG: Record<string, string> = {
  critical: "bg-red-500/15 text-red-300",
  high: "bg-orange-500/15 text-orange-300",
  medium: "bg-yellow-500/15 text-yellow-300",
  low: "bg-emerald-500/15 text-emerald-300",
  unknown: "bg-neutral-700/40 text-neutral-400",
};

export function SeverityPill({ severity }: { severity: string }) {
  const k = BG[severity] ?? BG.unknown;
  return (
    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide ${k}`}>
      {severity}
    </span>
  );
}
