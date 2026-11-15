import { useCallback, useEffect, useRef, useState } from "react";
import { subscribeTelemetry } from "../lib/ipc";
import type { TelemetryEvent, TelemetryEventOf, TelemetryKind } from "../lib/types";

export const TELEMETRY_CAPACITY = 5_000;
// Proxied traffic makes the event rate unbounded; flushing on a fixed tick caps React
// reconciliation at 10 Hz regardless of how fast the engine produces.
const FLUSH_MS = 100;

/** Progress of the most recent fuzzer run, folded from its telemetry events. */
export interface FuzzerProgress {
  id: string;
  total: number;
  /** Mutation cases finished; the baseline is not counted. */
  completed: number;
  faults: number;
  finished: boolean;
}

export interface TelemetryStore {
  events: readonly TelemetryEvent[];
  latestHeartbeat: TelemetryEventOf<"engineHeartbeat"> | null;
  latestProxyState: TelemetryEventOf<"proxyStateChanged"> | null;
  fuzzerProgress: FuzzerProgress | null;
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

function foldFuzzer(progress: FuzzerProgress | null, batch: readonly TelemetryEvent[]): FuzzerProgress | null {
  let next = progress;
  for (const event of batch) {
    if (event.kind === "fuzzerStarted") {
      next = { id: event.id, total: event.cases, completed: 0, faults: 0, finished: false };
    } else if (event.kind === "fuzzerCaseCompleted" && next?.id === event.id && event.result.class !== null) {
      next = {
        ...next,
        completed: next.completed + 1,
        faults: next.faults + (event.result.severity === "fault" ? 1 : 0),
      };
    } else if (event.kind === "fuzzerCompleted" && next?.id === event.id) {
      next = { ...next, faults: event.faults, finished: true };
    }
  }
  return next;
}

export function useTelemetry(): TelemetryStore {
  const [events, setEvents] = useState<readonly TelemetryEvent[]>([]);
  const [latestHeartbeat, setLatestHeartbeat] = useState<TelemetryStore["latestHeartbeat"]>(null);
  const [latestProxyState, setLatestProxyState] = useState<TelemetryStore["latestProxyState"]>(null);
  const [fuzzerProgress, setFuzzerProgress] = useState<FuzzerProgress | null>(null);
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
      if (batch.some((event) => event.kind.startsWith("fuzzer"))) {
        setFuzzerProgress((progress) => foldFuzzer(progress, batch));
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

  return { events, latestHeartbeat, latestProxyState, fuzzerProgress, paused, setPaused, clear, totalReceived };
}
