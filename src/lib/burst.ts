import type { BurstReport, BurstSyncMode } from "./types";

export const SYNC_MODES: readonly BurstSyncMode[] = ["preConnected", "lastByte"];

export const SYNC_LABEL: Record<BurstSyncMode, string> = {
  preConnected: "pre-connected",
  lastByte: "last byte",
};

/** Latest burst of each barrier sync mode in this session. */
export type SyncRuns = Readonly<Partial<Record<BurstSyncMode, BurstReport>>>;

/**
 * Two spreads compare only when the bursts sent the same request from the same number of
 * workers: the spread grows with the worker count, and another target has another handler.
 */
export function sameDispatch(a: BurstReport, b: BurstReport): boolean {
  return a.target === b.target && a.method === b.method && a.workers === b.workers;
}

/** Latest run of each sync mode that dispatched what `report` did, in `SYNC_MODES` order. */
export function comparableRuns(report: BurstReport, runs: SyncRuns): BurstReport[] {
  return SYNC_MODES.map((mode) => (mode === report.syncMode ? report : runs[mode])).filter(
    (run): run is BurstReport => run !== undefined && sameDispatch(run, report),
  );
}

/** Last-byte dispatch spread against the pre-connected one for the same request. */
export interface SpreadDelta {
  preConnectedUs: number;
  lastByteUs: number;
  /** Negative when holding the last byte narrowed the spread. */
  deltaUs: number;
  /** `lastByteUs / preConnectedUs`; `null` when the pre-connected spread was 0. */
  ratio: number | null;
}

/** `null` unless both modes ran the same request from as many workers and measured a spread. */
export function spreadDelta(runs: SyncRuns): SpreadDelta | null {
  const { preConnected, lastByte } = runs;
  if (preConnected === undefined || lastByte === undefined || !sameDispatch(preConnected, lastByte)) return null;
  const pre = preConnected.dispatchSpreadUs;
  const last = lastByte.dispatchSpreadUs;
  if (pre === null || last === null) return null;
  return { preConnectedUs: pre, lastByteUs: last, deltaUs: last - pre, ratio: pre === 0 ? null : last / pre };
}

/** `last byte 87 us narrower (0.71x)`, for the table footer and the report. */
export function describeDelta(delta: SpreadDelta, format: (us: number) => string): string {
  const direction = delta.deltaUs < 0 ? "narrower" : delta.deltaUs > 0 ? "wider" : "equal";
  const amount = delta.deltaUs === 0 ? "" : `${format(Math.abs(delta.deltaUs))} `;
  const ratio = delta.ratio === null ? "" : ` (${delta.ratio.toFixed(2)}x)`;
  return `last byte ${amount}${direction}${ratio}`;
}
