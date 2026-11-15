import { useCallback, useEffect, useRef, useState } from "react";
import { describeViolation } from "../lib/contract";
import { subscribeTelemetry } from "../lib/ipc";
import { emptyAuditCounts, type AuditKind } from "../lib/traffic";
import type { ContractViolation, Severity, TelemetryEvent, TelemetryEventOf, TelemetryKind } from "../lib/types";

export const TELEMETRY_CAPACITY = 5_000;
/** Audit records kept for the report; counters keep counting past it. */
export const AUDIT_CAPACITY = 1_000;
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

export type KindFilter =
  | "all"
  | "findings"
  | "proxy"
  | "burst"
  | "fuzzer"
  | "lab"
  | "scan"
  | "guard"
  | "probe"
  | "heartbeat";

/** `audit` narrows the `findings` view to one category; `null` shows every audited exchange. */
export interface TelemetryFilter {
  kind: KindFilter;
  audit: AuditKind | null;
}

/** One passive finding or contract violation, flattened from its proxy exchange. */
export interface AuditRecord {
  seq: number;
  tsUs: number;
  method: string;
  path: string;
  status: number | null;
  kind: AuditKind;
  severity: Severity;
  detail: string;
  evidence: string | null;
  /** Contract label of a drift record. */
  contract: string | null;
  violation: ContractViolation | null;
}

/** Folded from proxy exchanges as they arrive, independent of the table's ring buffer. */
export interface TrafficAudit {
  exchanges: number;
  counts: Record<AuditKind, number>;
  faults: number;
  /** Latest records, oldest first, at most `AUDIT_CAPACITY`. */
  records: readonly AuditRecord[];
}

export const EMPTY_AUDIT: TrafficAudit = { exchanges: 0, counts: emptyAuditCounts(), faults: 0, records: [] };

export interface TelemetryStore {
  events: readonly TelemetryEvent[];
  latestHeartbeat: TelemetryEventOf<"engineHeartbeat"> | null;
  latestProxyState: TelemetryEventOf<"proxyStateChanged"> | null;
  latestLabState: TelemetryEventOf<"labStateChanged"> | null;
  latestLabExchange: TelemetryEventOf<"labExchange"> | null;
  fuzzerProgress: FuzzerProgress | null;
  audit: TrafficAudit;
  filter: TelemetryFilter;
  setFilter: (filter: TelemetryFilter) => void;
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

function foldAudit(audit: TrafficAudit, batch: readonly TelemetryEvent[]): TrafficAudit {
  let exchanges = audit.exchanges;
  let faults = audit.faults;
  const counts = { ...audit.counts };
  const added: AuditRecord[] = [];
  for (const event of batch) {
    if (event.kind !== "proxyExchange") continue;
    exchanges += 1;
    const base = { seq: event.seq, tsUs: event.tsUs, method: event.method, path: event.path, status: event.status };
    for (const finding of event.findings) {
      counts[finding.kind] += 1;
      if (finding.severity === "fault") faults += 1;
      added.push({
        ...base,
        kind: finding.kind,
        severity: finding.severity,
        detail: finding.detail,
        evidence: finding.evidence,
        contract: null,
        violation: null,
      });
    }
    for (const violation of event.violations) {
      counts.contractDrift += 1;
      added.push({
        ...base,
        kind: "contractDrift",
        severity: "warn",
        detail: describeViolation(violation),
        evidence: event.contract,
        contract: event.contract,
        violation,
      });
    }
  }
  if (exchanges === audit.exchanges) return audit;
  const records = added.length === 0 ? audit.records : audit.records.concat(added).slice(-AUDIT_CAPACITY);
  return { exchanges, counts, faults, records };
}

export function useTelemetry(): TelemetryStore {
  const [events, setEvents] = useState<readonly TelemetryEvent[]>([]);
  const [latestHeartbeat, setLatestHeartbeat] = useState<TelemetryStore["latestHeartbeat"]>(null);
  const [latestProxyState, setLatestProxyState] = useState<TelemetryStore["latestProxyState"]>(null);
  const [latestLabState, setLatestLabState] = useState<TelemetryStore["latestLabState"]>(null);
  const [latestLabExchange, setLatestLabExchange] = useState<TelemetryStore["latestLabExchange"]>(null);
  const [fuzzerProgress, setFuzzerProgress] = useState<FuzzerProgress | null>(null);
  const [audit, setAudit] = useState<TrafficAudit>(EMPTY_AUDIT);
  const [filter, setFilter] = useState<TelemetryFilter>({ kind: "all", audit: null });
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
      const labState = findLast(batch, "labStateChanged");
      if (labState !== null) setLatestLabState(labState);
      const labExchange = findLast(batch, "labExchange");
      if (labExchange !== null) setLatestLabExchange(labExchange);
      if (batch.some((event) => event.kind.startsWith("fuzzer"))) {
        setFuzzerProgress((progress) => foldFuzzer(progress, batch));
      }
      // Audited like state: counters keep running while the table is paused.
      if (batch.some((event) => event.kind === "proxyExchange")) {
        setAudit((current) => foldAudit(current, batch));
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
    setAudit(EMPTY_AUDIT);
  }, []);

  return {
    events,
    latestHeartbeat,
    latestProxyState,
    latestLabState,
    latestLabExchange,
    fuzzerProgress,
    audit,
    filter,
    setFilter,
    paused,
    setPaused,
    clear,
    totalReceived,
  };
}
