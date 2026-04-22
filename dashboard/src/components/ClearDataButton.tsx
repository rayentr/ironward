"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";

export function ClearDataButton({
  demoCount,
  totalCount,
}: {
  demoCount: number;
  totalCount: number;
}) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [pending, start] = useTransition();
  const [status, setStatus] = useState<string | null>(null);

  if (totalCount === 0) return null;

  async function wipe(demoOnly: boolean) {
    setStatus(null);
    const res = await fetch("/api/admin/wipe", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ demoOnly }),
    });
    if (!res.ok) {
      setStatus(`Error (${res.status})`);
      return;
    }
    const body = (await res.json()) as { scansDeleted: number; findingsDeleted: number };
    setStatus(`Removed ${body.scansDeleted} scans · ${body.findingsDeleted} findings.`);
    start(() => router.refresh());
    setOpen(false);
  }

  return (
    <div className="relative inline-block">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="text-xs text-[var(--color-muted)] hover:text-white border border-[var(--color-border)] rounded-full px-3 py-1"
      >
        Clear data ▾
      </button>
      {open && (
        <div className="absolute right-0 mt-2 w-60 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] shadow-lg p-2 z-10">
          {demoCount > 0 && (
            <button
              type="button"
              onClick={() => wipe(true)}
              disabled={pending}
              className="w-full text-left text-sm px-3 py-2 rounded hover:bg-[var(--color-surface-2)] disabled:opacity-50"
            >
              Clear demo data only
              <div className="text-xs text-[var(--color-muted)]">{demoCount} demo scan{demoCount === 1 ? "" : "s"}</div>
            </button>
          )}
          <button
            type="button"
            onClick={() => {
              if (confirm("Delete ALL scan history? This cannot be undone.")) wipe(false);
            }}
            disabled={pending}
            className="w-full text-left text-sm px-3 py-2 rounded hover:bg-[var(--color-surface-2)] disabled:opacity-50 text-[var(--color-danger)]"
          >
            Clear all scan history
            <div className="text-xs text-[var(--color-muted)]">{totalCount} total scan{totalCount === 1 ? "" : "s"}</div>
          </button>
        </div>
      )}
      {status && <div className="absolute right-0 mt-2 text-xs text-[var(--color-muted)]">{status}</div>}
    </div>
  );
}
