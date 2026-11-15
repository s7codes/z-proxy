import { useCallback, useRef, useState } from "react";
import { cancelFuzzerSuite, runFuzzerSuite, type TransportError } from "../lib/ipc";
import type { EngineError, FuzzReport, FuzzSpec } from "../lib/types";

export interface FuzzerControl {
  running: boolean;
  cancelling: boolean;
  report: FuzzReport | null;
  error: EngineError | TransportError | null;
  run: (spec: FuzzSpec) => void;
  cancel: () => void;
}

export function useFuzzer(): FuzzerControl {
  const [running, setRunning] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [report, setReport] = useState<FuzzReport | null>(null);
  const [error, setError] = useState<FuzzerControl["error"]>(null);
  const inFlight = useRef(false);

  const run = useCallback((spec: FuzzSpec) => {
    // Guards against a double trigger (button + palette) before React re-renders `running`.
    if (inFlight.current) return;
    inFlight.current = true;
    setRunning(true);
    setCancelling(false);
    setError(null);
    void runFuzzerSuite(spec).then((result) => {
      inFlight.current = false;
      setRunning(false);
      setCancelling(false);
      if (result.ok) setReport(result.value);
      else setError(result.error);
    });
  }, []);

  const cancel = useCallback(() => {
    if (!inFlight.current) return;
    setCancelling(true);
    void cancelFuzzerSuite().then((result) => {
      if (!result.ok) {
        setCancelling(false);
        setError(result.error);
      }
    });
  }, []);

  return { running, cancelling, report, error, run, cancel };
}
