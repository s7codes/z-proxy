import { useEffect, useState } from "react";
import { getEngineStatus, ipcAvailable } from "../lib/ipc";
import type { EngineStatus, TelemetryEvent } from "../lib/types";

export type EngineLink =
  | { state: "connecting" }
  | { state: "unavailable"; reason: string }
  | { state: "online"; status: EngineStatus };

/**
 * Fetches the static engine descriptor once, then advances the live fields from the
 * heartbeat stream. No polling: the heartbeat is the clock.
 */
export function useEngineStatus(
  heartbeat: Extract<TelemetryEvent, { kind: "engineHeartbeat" }> | null,
): EngineLink {
  const [link, setLink] = useState<EngineLink>(
    ipcAvailable
      ? { state: "connecting" }
      : { state: "unavailable", reason: "Tauri runtime not detected" },
  );

  useEffect(() => {
    if (!ipcAvailable) return;
    let cancelled = false;
    void getEngineStatus().then((result) => {
      if (cancelled) return;
      setLink(
        result.ok
          ? { state: "online", status: result.value }
          : { state: "unavailable", reason: result.error.message },
      );
    });
    return () => {
      cancelled = true;
    };
  }, []);

  if (link.state !== "online" || heartbeat === null) return link;
  return {
    state: "online",
    status: {
      ...link.status,
      uptimeMs: heartbeat.uptimeMs,
      telemetrySubscribers: heartbeat.subscribers,
    },
  };
}
