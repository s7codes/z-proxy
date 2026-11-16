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
