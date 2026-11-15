import { useCallback, useRef, useState } from "react";
import { pickProjectRoot, scanProjectRoutes, type TransportError } from "../lib/ipc";
import type { EngineError, RouteScanReport } from "../lib/types";

const ROOT_KEY = "zproxy.scanRoot";

export interface RouteScanControl {
  root: string;
  setRoot: (root: string) => void;
  scanning: boolean;
  report: RouteScanReport | null;
  error: EngineError | TransportError | null;
  scan: (root?: string) => void;
  browse: () => void;
  /** Shows a report produced elsewhere (the target lab) without touching the project root. */
  adopt: (report: RouteScanReport) => void;
}

function readStoredRoot(): string {
  try {
    return window.localStorage.getItem(ROOT_KEY) ?? "";
  } catch {
    return "";
  }
}

function storeRoot(root: string): void {
  try {
    window.localStorage.setItem(ROOT_KEY, root);
  } catch {
    // Storage can be unavailable (private mode, quota); the root is a convenience only.
  }
}

export function useRouteScan(): RouteScanControl {
  const [root, setRoot] = useState(readStoredRoot);
  const [scanning, setScanning] = useState(false);
  const [report, setReport] = useState<RouteScanReport | null>(null);
  const [error, setError] = useState<RouteScanControl["error"]>(null);
  const inFlight = useRef(false);
  const rootRef = useRef(root);
  rootRef.current = root;

  const scan = useCallback((override?: string) => {
    const target = (override ?? rootRef.current).trim();
    if (inFlight.current || target === "") return;
    inFlight.current = true;
    setScanning(true);
    setError(null);
    void scanProjectRoutes(target).then((result) => {
      inFlight.current = false;
      setScanning(false);
      if (result.ok) {
        setReport(result.value);
        setRoot(result.value.root);
        storeRoot(result.value.root);
      } else {
        setError(result.error);
      }
    });
  }, []);

  const browse = useCallback(() => {
    void pickProjectRoot().then((result) => {
      if (!result.ok) {
        setError(result.error);
        return;
      }
      if (result.value === null) return;
      setRoot(result.value);
      scan(result.value);
    });
  }, [scan]);

  const adopt = useCallback((next: RouteScanReport) => {
    setReport(next);
    setError(null);
  }, []);

  return { root, setRoot, scanning, report, error, scan, browse, adopt };
}
