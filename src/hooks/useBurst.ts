import { useCallback, useRef, useState } from "react";
import { runConcurrencyBurst, type TransportError } from "../lib/ipc";
import type { BurstReport, BurstSpec, EngineError } from "../lib/types";

export interface BurstControl {
  running: boolean;
  report: BurstReport | null;
  error: EngineError | TransportError | null;
  fire: (spec: BurstSpec) => void;
}

export function useBurst(): BurstControl {
  const [running, setRunning] = useState(false);
  const [report, setReport] = useState<BurstReport | null>(null);
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
      if (result.ok) setReport(result.value);
      else setError(result.error);
    });
  }, []);

  return { running, report, error, fire };
}
