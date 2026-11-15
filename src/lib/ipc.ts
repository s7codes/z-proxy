import { Channel, invoke, isTauri } from "@tauri-apps/api/core";
import type {
  BurstReport,
  BurstSpec,
  EngineError,
  EngineErrorCode,
  EngineStatus,
  FaultProfile,
  FaultRule,
  FuzzCasePayload,
  FuzzCaseRef,
  FuzzReport,
  FuzzSpec,
  LabConfig,
  LabMode,
  LabStatus,
  ProxyConfig,
  ProxyStatus,
  RouteScanReport,
  TelemetryEvent,
  ValidatedTarget,
} from "./types";

export type IpcResult<T> =
  | { ok: true; value: T }
  | { ok: false; error: EngineError | TransportError };

/** Failure outside the engine's domain: no Tauri runtime, IPC serialization, unknown command. */
export interface TransportError {
  code: "IPC_UNAVAILABLE" | "IPC_FAILURE";
  message: string;
}

const ENGINE_CODES: ReadonlySet<string> = new Set<EngineErrorCode>([
  "NON_LOOPBACK_TARGET_REJECTED",
  "INVALID_TARGET",
  "UNSUPPORTED_SCHEME",
  "PLAINTEXT_ONLY",
  "CLIENT_BUILD_FAILED",
  "PROXY_ALREADY_RUNNING",
  "LISTENER_BIND_FAILED",
  "PROXY_LOOP",
  "INVALID_FAULT_PROFILE",
  "INVALID_FAULT_RULE",
  "INVALID_BURST_SPEC",
  "INVALID_FUZZ_SPEC",
  "FUZZER_BUSY",
  "INVALID_SCAN_ROOT",
  "LAB_ALREADY_RUNNING",
  "INTERNAL_TASK_FAILED",
]);

export function isEngineError(value: unknown): value is EngineError {
  if (typeof value !== "object" || value === null) return false;
  const code: unknown = Reflect.get(value, "code");
  const message: unknown = Reflect.get(value, "message");
  return typeof code === "string" && ENGINE_CODES.has(code) && typeof message === "string";
}

export function isTransportError(error: EngineError | TransportError): error is TransportError {
  return error.code === "IPC_UNAVAILABLE" || error.code === "IPC_FAILURE";
}

export const ipcAvailable = isTauri();

async function call<T>(command: string, args?: Record<string, unknown>): Promise<IpcResult<T>> {
  if (!ipcAvailable) {
    return {
      ok: false,
      error: { code: "IPC_UNAVAILABLE", message: "Tauri runtime not detected" },
    };
  }
  try {
    const value = await invoke<T>(command, args);
    return { ok: true, value };
  } catch (raw: unknown) {
    if (isEngineError(raw)) return { ok: false, error: raw };
    return {
      ok: false,
      error: { code: "IPC_FAILURE", message: raw instanceof Error ? raw.message : String(raw) },
    };
  }
}

export function validateTarget(input: string): Promise<IpcResult<ValidatedTarget>> {
  return call<ValidatedTarget>("validate_target", { input });
}

export function getEngineStatus(): Promise<IpcResult<EngineStatus>> {
  return call<EngineStatus>("get_engine_status");
}

export function startProxy(config: ProxyConfig): Promise<IpcResult<ProxyStatus>> {
  return call<ProxyStatus>("start_proxy", { config });
}

export function stopProxy(): Promise<IpcResult<ProxyStatus>> {
  return call<ProxyStatus>("stop_proxy");
}

export function getProxyStatus(): Promise<IpcResult<ProxyStatus>> {
  return call<ProxyStatus>("get_proxy_status");
}

export function setFaultProfile(armed: boolean, profile: FaultProfile): Promise<IpcResult<ProxyStatus>> {
  return call<ProxyStatus>("set_fault_profile", { armed, profile });
}

/** Replaces the whole rule set; an invalid rule rejects the set and keeps the active one. */
export function setFaultRules(rules: FaultRule[]): Promise<IpcResult<ProxyStatus>> {
  return call<ProxyStatus>("set_fault_rules", { rules });
}

export function runConcurrencyBurst(spec: BurstSpec): Promise<IpcResult<BurstReport>> {
  return call<BurstReport>("run_concurrency_burst", { spec });
}

export function runFuzzerSuite(spec: FuzzSpec): Promise<IpcResult<FuzzReport>> {
  return call<FuzzReport>("run_fuzzer_suite", { spec });
}

/** Rebuilds one case's request body from a report's base body and classes. */
export function materializeFuzzCase(reference: FuzzCaseRef): Promise<IpcResult<FuzzCasePayload>> {
  return call<FuzzCasePayload>("materialize_fuzz_case", { reference });
}

/** `true` when a running suite was asked to stop; it ends after the in-flight case. */
export function cancelFuzzerSuite(): Promise<IpcResult<boolean>> {
  return call<boolean>("cancel_fuzzer_suite");
}

export function scanProjectRoutes(root: string): Promise<IpcResult<RouteScanReport>> {
  return call<RouteScanReport>("scan_project_routes", { root });
}

/** Resolves to `null` when the operator cancels the dialog. */
export function pickProjectRoot(): Promise<IpcResult<string | null>> {
  return call<string | null>("pick_project_root");
}

export function startLabServer(config: LabConfig): Promise<IpcResult<LabStatus>> {
  return call<LabStatus>("start_lab_server", { config });
}

export function stopLabServer(): Promise<IpcResult<LabStatus>> {
  return call<LabStatus>("stop_lab_server");
}

/** Applies on the next request without a restart; clears the coupon ledger. */
export function setLabMode(mode: LabMode): Promise<IpcResult<LabStatus>> {
  return call<LabStatus>("set_lab_mode", { mode });
}

export function resetLabState(): Promise<IpcResult<LabStatus>> {
  return call<LabStatus>("reset_lab_state");
}

export function getLabStatus(): Promise<IpcResult<LabStatus>> {
  return call<LabStatus>("get_lab_status");
}

/** Routes parsed from the lab's own OpenAPI document, shaped like a scan report. */
export function getLabRoutes(): Promise<IpcResult<RouteScanReport>> {
  return call<RouteScanReport>("get_lab_routes");
}

export interface TelemetrySubscription {
  close(): void;
}

export function subscribeTelemetry(
  onEvent: (event: TelemetryEvent) => void,
): TelemetrySubscription {
  if (!ipcAvailable) return { close: () => undefined };

  const channel = new Channel<TelemetryEvent>();
  channel.onmessage = onEvent;
  const pending = call<number>("subscribe_telemetry", { onEvent: channel });
  let closed = false;

  return {
    close() {
      if (closed) return;
      closed = true;
      channel.onmessage = () => undefined;
      void pending.then((result) => {
        if (result.ok) {
          void call<boolean>("unsubscribe_telemetry", { subscriptionId: result.value });
        }
      });
    },
  };
}
