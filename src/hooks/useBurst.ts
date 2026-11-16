import { useCallback, useRef, useState } from "react";
import type { SyncRuns } from "../lib/burst";
import { runConcurrencyBurst, type TransportError } from "../lib/ipc";
import type { BurstReport, BurstSpec, EngineError } from "../lib/types";

export interface BurstControl {
  running: boolean;
  report: BurstReport | null;
  /** Latest report of each sync mode, so a spread can be read against the other mode's. */
  bySync: SyncRuns;
  error: EngineError | TransportError | null;
  fire: (spec: BurstSpec) => void;
}

export function useBurst(): BurstControl {
  const [running, setRunning] = useState(false);
  const [report, setReport] = useState<BurstReport | null>(null);
  const [bySync, setBySync] = useState<SyncRuns>({});
  const [error, setError] = useState<BurstControl["error"]>(null);
  const inFlight = useRef(false);

  const fire = useCallback((spec: BurstSpec) => {
    // Guards against a double trigger (button + palette) before React re-renders `running`.
    if (inFlight.current) return;
    inFlight.current = true;
    setRunning(true);
    setError(null);
    void runConcurrencyBurst(spec).then((result) => {
      inFlight.current = false;
      setRunning(false);
      if (result.ok) {
        const finished = result.value;
        setReport(finished);
        setBySync((current) => ({ ...current, [finished.syncMode]: finished }));
      } else {
        setError(result.error);
      }
    });
  }, []);

  return { running, report, bySync, error, fire };
}
