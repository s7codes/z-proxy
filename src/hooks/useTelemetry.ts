import { useCallback, useEffect, useRef, useState } from "react";
import { subscribeTelemetry } from "../lib/ipc";
import type { TelemetryEvent } from "../lib/types";

export const TELEMETRY_CAPACITY = 5_000;
// Event rate will be unbounded once the proxy streams requests; flushing on a fixed tick
// caps React reconciliation at 10 Hz regardless of how fast the engine produces.
const FLUSH_MS = 100;

export interface TelemetryStore {
  events: readonly TelemetryEvent[];
  latestHeartbeat: Extract<TelemetryEvent, { kind: "engineHeartbeat" }> | null;
  paused: boolean;
  setPaused: (paused: boolean) => void;
  clear: () => void;
  totalReceived: number;
}

export function useTelemetry(): TelemetryStore {
  const [events, setEvents] = useState<readonly TelemetryEvent[]>([]);
  const [latestHeartbeat, setLatestHeartbeat] =
    useState<TelemetryStore["latestHeartbeat"]>(null);
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
      for (let i = batch.length - 1; i >= 0; i--) {
        const event = batch[i];
        if (event?.kind === "engineHeartbeat") {
          setLatestHeartbeat(event);
          break;
        }
      }
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

  return { events, latestHeartbeat, paused, setPaused, clear, totalReceived };
}
