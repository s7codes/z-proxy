export function formatLatency(us: number): string {
  if (us < 1_000) return `${us} µs`;
  if (us < 1_000_000) return `${(us / 1_000).toFixed(2)} ms`;
  return `${(us / 1_000_000).toFixed(3)} s`;
}

export function formatUptime(ms: number): string {
  const total = Math.floor(ms / 1_000);
  const h = Math.floor(total / 3_600);
  const m = Math.floor((total % 3_600) / 60);
  const s = total % 60;
  return `${pad(h)}:${pad(m)}:${pad(s)}`;
}

/** HH:MM:SS.mmmuuu in local time, from a UNIX-epoch microsecond timestamp. */
export function formatTimestamp(tsUs: number): string {
  const date = new Date(Math.floor(tsUs / 1_000));
  const micros = tsUs % 1_000_000;
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}.${String(micros).padStart(6, "0")}`;
}

export function formatCount(n: number): string {
  return n.toLocaleString("en-US");
}

function pad(n: number): string {
  return String(n).padStart(2, "0");
}

export function formatBytes(n: number): string {
  if (n < 1_024) return `${n} B`;
  if (n < 1_048_576) return `${(n / 1_024).toFixed(1)} KiB`;
  return `${(n / 1_048_576).toFixed(2)} MiB`;
}

export function formatPercent(part: number, total: number): string {
  return total === 0 ? "0.0%" : `${((part / total) * 100).toFixed(1)}%`;
}
