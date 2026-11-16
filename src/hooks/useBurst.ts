import { useCallback, useRef, useState } from "react";
import { SYNC_MODES, type SyncRuns } from "../lib/burst";
import { runConcurrencyBurst, type TransportError } from "../lib/ipc";
import type { BurstReport, BurstSpec, BurstSyncMode, EngineError } from "../lib/types";

/** Position of a sync comparison while it runs. */
export interface CompareStep {
  mode: BurstSyncMode;
  step: number;
  of: number;
}

export interface BurstControl {
  running: boolean;
  report: BurstReport | null;
  /** Latest report of each sync mode, so a spread can be read against the other mode's. */
  bySync: SyncRuns;
  /** Mode a comparison is running; `null` outside one. */
  comparing: CompareStep | null;
  error: EngineError | TransportError | null;
  fire: (spec: BurstSpec) => void;
  /**
   * Runs `spec` once per sync mode in `SYNC_MODES` order (pre-connected, then last byte) and
   * leaves the last run as `report`, so the spread table compares one request from as many
   * workers. A failed run ends the comparison.
   */
  compare: (spec: BurstSpec) => void;
}

export function useBurst(): BurstControl {
  const [running, setRunning] = useState(false);
  const [report, setReport] = useState<BurstReport | null>(null);
  const [bySync, setBySync] = useState<SyncRuns>({});
  const [comparing, setComparing] = useState<CompareStep | null>(null);
  const [error, setError] = useState<BurstControl["error"]>(null);
  const inFlight = useRef(false);

  // Guards against a double trigger (button + palette) before React re-renders `running`.
  const begin = useCallback((): boolean => {
    if (inFlight.current) return false;
    inFlight.current = true;
    setRunning(true);
    setError(null);
    return true;
  }, []);

  const end = useCallback(() => {
    inFlight.current = false;
    setComparing(null);
    setRunning(false);
  }, []);

  const record = useCallback((finished: BurstReport) => {
    setReport(finished);
    setBySync((current) => ({ ...current, [finished.syncMode]: finished }));
  }, []);

  const fire = useCallback(
    (spec: BurstSpec) => {
      if (!begin()) return;
      void runConcurrencyBurst(spec).then((result) => {
        if (result.ok) record(result.value);
        else setError(result.error);
        end();
      });
    },
    [begin, end, record],
  );

  const compare = useCallback(
    (spec: BurstSpec) => {
      if (!begin()) return;
      void (async () => {
        for (const [index, mode] of SYNC_MODES.entries()) {
          setComparing({ mode, step: index + 1, of: SYNC_MODES.length });
          const result = await runConcurrencyBurst({ ...spec, syncMode: mode });
          if (!result.ok) {
            setError(result.error);
            break;
          }
          record(result.value);
        }
        end();
      })();
    },
    [begin, end, record],
  );

  return { running, report, bySync, comparing, error, fire, compare };
}
