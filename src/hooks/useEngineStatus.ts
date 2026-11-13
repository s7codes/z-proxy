import { useEffect, useState } from "react";
import { getEngineStatus, ipcAvailable } from "../lib/ipc";
import type { EngineStatus, TelemetryEventOf } from "../lib/types";

export type EngineLink =
  | { state: "connecting" }
  | { state: "unavailable"; reason: string }
  | { state: "online"; status: EngineStatus };

/**
 * Fetches the static engine descriptor once, then advances the live fields from the
 * telemetry stream. No polling: the heartbeat is the clock and proxy state changes are
 * pushed by the engine.
 */
export function useEngineStatus(
  heartbeat: TelemetryEventOf<"engineHeartbeat"> | null,
  proxyState: TelemetryEventOf<"proxyStateChanged"> | null,
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

  if (link.state !== "online") return link;
  return {
    state: "online",
    status: {
      ...link.status,
      ...(heartbeat === null
        ? {}
        : { uptimeMs: heartbeat.uptimeMs, telemetrySubscribers: heartbeat.subscribers }),
      ...(proxyState === null ? {} : { proxyListener: proxyState.status.listener }),
    },
  };
}
