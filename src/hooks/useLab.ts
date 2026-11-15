import { useCallback, useEffect, useMemo, useState } from "react";
import {
  getLabRoutes,
  getLabStatus,
  ipcAvailable,
  resetLabState,
  setLabMode,
  startLabServer,
  stopLabServer,
  type IpcResult,
  type TransportError,
} from "../lib/ipc";
import type { EngineError, LabCounters, LabMode, LabStatus, RouteScanReport, TelemetryEventOf } from "../lib/types";

export interface LabControl {
  /** Engine-side truth; `null` until the first status arrives. */
  status: LabStatus | null;
  /** Latest counters: from per-request exchanges, which arrive between state events. */
  counters: LabCounters | null;
  busy: boolean;
  error: EngineError | TransportError | null;
  start: (mode: LabMode) => void;
  stop: () => void;
  setMode: (mode: LabMode) => void;
  reset: () => void;
  loadRoutes: () => Promise<RouteScanReport | null>;
}

export function useLab(
  latestState: TelemetryEventOf<"labStateChanged"> | null,
  latestExchange: TelemetryEventOf<"labExchange"> | null,
): LabControl {
  const [status, setStatus] = useState<LabStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<LabControl["error"]>(null);

  useEffect(() => {
    if (!ipcAvailable) return;
    let cancelled = false;
    void getLabStatus().then((result) => {
      if (!cancelled && result.ok) setStatus(result.value);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (latestState !== null) setStatus(latestState.status);
  }, [latestState]);

  // State events and exchanges share one sequence, so the higher `seq` holds the newer
  // counters; a reset must not be overwritten by an exchange that preceded it.
  const counters = useMemo(() => {
    if (latestExchange !== null && (latestState === null || latestExchange.seq > latestState.seq)) {
      return latestExchange.counters;
    }
    return latestState?.status.counters ?? status?.counters ?? null;
  }, [latestExchange, latestState, status]);

  const settle = useCallback((result: IpcResult<LabStatus>) => {
    setBusy(false);
    if (result.ok) {
      setStatus(result.value);
      setError(null);
    } else {
      setError(result.error);
    }
  }, []);

  const start = useCallback(
    (mode: LabMode) => {
      setBusy(true);
      void startLabServer({ port: null, mode }).then(settle);
    },
    [settle],
  );

  const stop = useCallback(() => {
    setBusy(true);
    void stopLabServer().then(settle);
  }, [settle]);

  const setMode = useCallback(
    (mode: LabMode) => {
      void setLabMode(mode).then(settle);
    },
    [settle],
  );

  const reset = useCallback(() => {
    void resetLabState().then(settle);
  }, [settle]);

  const loadRoutes = useCallback(async () => {
    const result = await getLabRoutes();
    if (result.ok) return result.value;
    setError(result.error);
    return null;
  }, []);

  return { status, counters, busy, error, start, stop, setMode, reset, loadRoutes };
}
