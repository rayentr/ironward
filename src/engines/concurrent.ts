import { cpus } from "node:os";

/**
 * Process an array of items with bounded concurrency.
 * Callers get results in input order, but the `onResult` callback fires
 * as each item completes — preserving streaming output.
 */
export async function mapConcurrent<T, R>(
  items: T[],
  concurrency: number,
  worker: (item: T, index: number) => Promise<R>,
  onResult?: (result: R, index: number) => void,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;

  async function runOne(): Promise<void> {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      const r = await worker(items[i], i);
      results[i] = r;
      if (onResult) onResult(r, i);
    }
  }

  const n = Math.max(1, Math.min(concurrency, items.length));
  const runners: Promise<void>[] = [];
  for (let k = 0; k < n; k++) runners.push(runOne());
  await Promise.all(runners);
  return results;
}

/**
 * Reasonable default concurrency for I/O-bound file scanning.
 * Capped low because libuv's default thread pool is 4, and going
 * above that thrashes without speeding things up.
 */
export function defaultConcurrency(): number {
  const envOverride = Number.parseInt(process.env.IRONWARD_CONCURRENCY ?? "", 10);
  if (Number.isFinite(envOverride) && envOverride > 0) return envOverride;
  const cpuCount = cpus().length;
  return Math.max(2, Math.min(8, cpuCount));
}
