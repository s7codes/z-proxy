import { useCallback, useEffect, useState } from "react";
import {
  getProxyStatus,
  ipcAvailable,
  setFaultProfile,
  startProxy,
  stopProxy,
  type IpcResult,
  type TransportError,
} from "../lib/ipc";
import type { EngineError, FaultProfile, ProxyStatus, TelemetryEventOf } from "../lib/types";

export interface ProxyControl {
  /** Engine-side truth; `null` until the first status arrives. */
  status: ProxyStatus | null;
  busy: boolean;
  error: EngineError | TransportError | null;
  start: (upstream: string, listenPort: number) => void;
  stop: () => void;
  applyFaults: (armed: boolean, profile: FaultProfile) => void;
}

export function useProxy(latest: TelemetryEventOf<"proxyStateChanged"> | null): ProxyControl {
  const [status, setStatus] = useState<ProxyStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ProxyControl["error"]>(null);

  useEffect(() => {
    if (!ipcAvailable) return;
    let cancelled = false;
    void getProxyStatus().then((result) => {
      if (!cancelled && result.ok) setStatus(result.value);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (latest !== null) setStatus(latest.status);
  }, [latest]);

  const settle = useCallback((result: IpcResult<ProxyStatus>) => {
    setBusy(false);
    if (result.ok) {
      setStatus(result.value);
      setError(null);
    } else {
      setError(result.error);
    }
  }, []);

  const start = useCallback(
    (upstream: string, listenPort: number) => {
      setBusy(true);
      void startProxy({ upstream, listenPort }).then(settle);
    },
    [settle],
  );

  const stop = useCallback(() => {
    setBusy(true);
    void stopProxy().then(settle);
  }, [settle]);

  // Fault updates do not toggle `busy`: they are pushed while the operator drags sliders
  // and must not disable the controls being dragged.
  const applyFaults = useCallback((armed: boolean, profile: FaultProfile) => {
    void setFaultProfile(armed, profile).then((result) => {
      if (result.ok) {
        setStatus(result.value);
        setError(null);
      } else {
        setError(result.error);
      }
    });
  }, []);

  return { status, busy, error, start, stop, applyFaults };
}

export function sameProfile(a: FaultProfile, b: FaultProfile): boolean {
  return (
    a.latencyMs === b.latencyMs &&
    a.jitterMs === b.jitterMs &&
    a.dropRate === b.dropRate &&
    a.statusMutation === b.statusMutation &&
    a.mutationRate === b.mutationRate
  );
}
