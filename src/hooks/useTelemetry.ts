import { useCallback, useEffect, useRef, useState } from "react";
import { subscribeTelemetry } from "../lib/ipc";
import type { TelemetryEvent, TelemetryEventOf, TelemetryKind } from "../lib/types";

export const TELEMETRY_CAPACITY = 5_000;
// Proxied traffic makes the event rate unbounded; flushing on a fixed tick caps React
// reconciliation at 10 Hz regardless of how fast the engine produces.
const FLUSH_MS = 100;

export interface TelemetryStore {
  events: readonly TelemetryEvent[];
  latestHeartbeat: TelemetryEventOf<"engineHeartbeat"> | null;
  latestProxyState: TelemetryEventOf<"proxyStateChanged"> | null;
  paused: boolean;
  setPaused: (paused: boolean) => void;
  clear: () => void;
  totalReceived: number;
}

function findLast<K extends TelemetryKind>(
  batch: readonly TelemetryEvent[],
  kind: K,
): TelemetryEventOf<K> | null {
  for (let i = batch.length - 1; i >= 0; i--) {
    const event = batch[i];
    if (event?.kind === kind) return event as TelemetryEventOf<K>;
  }
  return null;
}

export function useTelemetry(): TelemetryStore {
  const [events, setEvents] = useState<readonly TelemetryEvent[]>([]);
  const [latestHeartbeat, setLatestHeartbeat] = useState<TelemetryStore["latestHeartbeat"]>(null);
  const [latestProxyState, setLatestProxyState] = useState<TelemetryStore["latestProxyState"]>(null);
  const [paused, setPaused] = useState(false);
  const [totalReceived, setTotalReceived] = useState(0);

  const pending = useRef<TelemetryEvent[]>([]);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  useEffect(() => {
    const subscription = subscribeTelemetry((event) => {
      pending.current.push(event);
    });

    const timer = window.setInterval(() => {
      const batch = pending.current;
      if (batch.length === 0) return;
      pending.current = [];

      setTotalReceived((n) => n + batch.length);
      const heartbeat = findLast(batch, "engineHeartbeat");
      if (heartbeat !== null) setLatestHeartbeat(heartbeat);
      // State events are applied even while the table is paused: they drive controls,
      // not just the log.
      const proxyState = findLast(batch, "proxyStateChanged");
      if (proxyState !== null) setLatestProxyState(proxyState);

      if (pausedRef.current) return;
      setEvents((prev) => {
        const next = prev.concat(batch);
        return next.length > TELEMETRY_CAPACITY ? next.slice(next.length - TELEMETRY_CAPACITY) : next;
      });
    }, FLUSH_MS);

    return () => {
      window.clearInterval(timer);
      subscription.close();
    };
  }, []);

  const clear = useCallback(() => {
    pending.current = [];
    setEvents([]);
  }, []);

  return { events, latestHeartbeat, latestProxyState, paused, setPaused, clear, totalReceived };
}
