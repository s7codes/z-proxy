import { memo, useEffect, useMemo, useRef, useState, type Ref } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { TelemetryStore } from "../../hooks/useTelemetry";
import { SYNC_LABEL } from "../../lib/burst";
import { summarizeViolations } from "../../lib/contract";
import { AUDIT_SHORT, type AuditKind } from "../../lib/traffic";
import { DISCLOSURE_LABEL } from "../../lib/disclosure";
import { formatBytes, formatLatency, formatTimestamp, formatUptime } from "../../lib/format";
import { ipcAvailable } from "../../lib/ipc";
import { describePartialDrop } from "../../lib/rules";
import { httpStatusTone, TONE_BG, TONE_TEXT, type Tone } from "../../lib/tone";
import type { FaultProfile, FuzzVerdict, TelemetryEvent } from "../../lib/types";
import { FILTER_KINDS, TelemetryToolbar } from "./TelemetryToolbar";

const ROW_HEIGHT = 20;
const GRID = "grid grid-cols-[4px_56px_116px_60px_minmax(180px,1.5fr)_72px_84px_minmax(160px,1fr)]";
const CELL = "truncate px-1.5";

export interface Row {
  key: string;
  seq: number;
  time: string;
  kind: string;
  kindTone: Tone;
  target: string;
  result: string;
  resultTone: Tone;
  latency: string;
  detail: string;
}

/** Whole-row tint for flagged rows, as a capture tool colors error frames. */
const ROW_TINT: Record<Tone, string> = {
  fault: "bg-fault/12",
  warn: "bg-warn/10",
  ok: "",
  muted: "",
};

function audited(event: TelemetryEvent, audit: AuditKind | null): boolean {
  if (event.kind !== "proxyExchange") return false;
  if (audit === null) return event.findings.length > 0 || event.violations.length > 0;
  if (audit === "contractDrift") return event.violations.length > 0;
  return event.findings.some((finding) => finding.kind === audit);
}

function matches(row: Row, needle: string): boolean {
  return (
    row.target.toLowerCase().includes(needle) ||
    row.result.toLowerCase().includes(needle) ||
    row.detail.toLowerCase().includes(needle) ||
    row.kind.toLowerCase().includes(needle)
  );
}

interface TelemetryTableProps {
  store: TelemetryStore;
  selected: number | null;
  onSelect: (seq: number) => void;
  queryRef: Ref<HTMLInputElement>;
}

export function TelemetryTable({ store, selected, onSelect, queryRef }: TelemetryTableProps) {
  const { filter, setFilter } = store;
  const [query, setQuery] = useState("");
  const scrollRef = useRef<HTMLDivElement>(null);
  const stickToBottom = useRef(true);

  const rows = useMemo(() => {
    const { kind, audit } = filter;
    const source =
      kind === "all"
        ? store.events
        : kind === "findings"
          ? store.events.filter((e) => audited(e, audit))
          : store.events.filter((e) => FILTER_KINDS[kind].has(e.kind));
    const mapped = source.map(toRow);
    const needle = query.trim().toLowerCase();
    return needle === "" ? mapped : mapped.filter((row) => matches(row, needle));
  }, [store.events, filter, query]);

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 24,
  });

  useEffect(() => {
    if (stickToBottom.current && rows.length > 0) {
      virtualizer.scrollToIndex(rows.length - 1, { align: "end" });
    }
  }, [rows.length, virtualizer]);

  const step = (delta: number | "first" | "last") => {
    if (rows.length === 0) return;
    const current = rows.findIndex((row) => row.seq === selected);
    const index =
      delta === "first"
        ? 0
        : delta === "last"
          ? rows.length - 1
          : current === -1
            ? delta > 0
              ? 0
              : rows.length - 1
            : Math.min(rows.length - 1, Math.max(0, current + delta));
    const row = rows[index];
    if (row === undefined) return;
    // Moving the cursor away from the tail is a request to stop following the stream.
    stickToBottom.current = index === rows.length - 1;
    onSelect(row.seq);
    virtualizer.scrollToIndex(index, { align: "auto" });
  };

  return (
    <div className="flex h-full flex-col bg-bg">
      <TelemetryToolbar
        filter={filter}
        onFilter={setFilter}
        query={query}
        onQuery={setQuery}
        queryRef={queryRef}
        audit={store.audit}
      />
      <div
        className={`${GRID} h-[22px] shrink-0 items-center border-b border-line-strong bg-panel text-xs text-fg-dim`}
        role="row"
      >
        <span />
        <HeaderCell label="No." align="right" />
        <HeaderCell label="Time" />
        <HeaderCell label="Source" />
        <HeaderCell label="Request" />
        <HeaderCell label="Status" />
        <HeaderCell label="Duration" align="right" />
        <HeaderCell label="Info" last />
      </div>
      <div
        ref={scrollRef}
        tabIndex={0}
        role="grid"
        aria-label="Engine events"
        className="relative min-h-0 flex-1 overflow-auto outline-none"
        onScroll={(e) => {
          const el = e.currentTarget;
          stickToBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < ROW_HEIGHT * 2;
        }}
        onKeyDown={(e) => {
          const page = Math.max(1, Math.floor(e.currentTarget.clientHeight / ROW_HEIGHT) - 1);
          const moves: Record<string, number | "first" | "last"> = {
            ArrowDown: 1,
            ArrowUp: -1,
            PageDown: page,
            PageUp: -page,
            Home: "first",
            End: "last",
          };
          const move = moves[e.key];
          if (move === undefined) return;
          e.preventDefault();
          step(move);
        }}
      >
        {rows.length === 0 ? (
          <EmptyState paused={store.paused} hasFilter={(filter.kind !== "all" || query !== "") && store.events.length > 0} />
        ) : (
          <div style={{ height: virtualizer.getTotalSize() }} className="relative w-full">
            {virtualizer.getVirtualItems().map((item) => {
              const row = rows[item.index];
              if (row === undefined) return null;
              return (
                <TableRow
                  key={row.key}
                  row={row}
                  top={item.start}
                  odd={item.index % 2 === 1}
                  selected={row.seq === selected}
                  onSelect={onSelect}
                />
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

function HeaderCell({ label, align = "left", last = false }: { label: string; align?: "left" | "right"; last?: boolean }) {
  return (
    <span
      role="columnheader"
      className={`flex h-full items-center px-1.5 ${align === "right" ? "justify-end" : ""} ${last ? "" : "border-r border-line"}`}
    >
      {label}
    </span>
  );
}

const TableRow = memo(function TableRow({
  row,
  top,
  odd,
  selected,
  onSelect,
}: {
  row: Row;
  top: number;
  odd: boolean;
  selected: boolean;
  onSelect: (seq: number) => void;
}) {
  const tint = ROW_TINT[row.kindTone];
  const surface = selected ? "bg-select text-select-fg" : tint !== "" ? tint : odd ? "bg-zebra" : "";
  const tone = (t: Tone, fallback: string) => (selected ? "" : t === "muted" ? fallback : TONE_TEXT[t]);
  return (
    <div
      role="row"
      aria-selected={selected}
      onMouseDown={() => onSelect(row.seq)}
      className={`${GRID} num absolute left-0 w-full items-center text-xs ${surface}`}
      style={{ height: ROW_HEIGHT, transform: `translateY(${top}px)` }}
    >
      <span className={`h-full ${row.kindTone === "muted" ? "" : TONE_BG[row.kindTone]}`} aria-hidden />
      <span className={`${CELL} text-right ${selected ? "" : "text-fg-faint"}`}>{row.seq}</span>
      <span className={`${CELL} ${selected ? "" : "text-fg-dim"}`}>{row.time}</span>
      <span className={`${CELL} font-sans ${selected ? "" : "text-fg-dim"}`}>{row.kind}</span>
      <span className={`${CELL} ${selected ? "" : "text-fg-bright"}`} title={row.target}>
        {row.target}
      </span>
      <span className={`${CELL} ${tone(row.resultTone, "text-fg-dim")}`}>{row.result}</span>
      <span className={`${CELL} text-right ${selected ? "" : "text-fg-dim"}`}>{row.latency}</span>
      <span className={`${CELL} ${selected ? "" : "text-fg-dim"}`} title={row.detail}>
        {row.detail}
      </span>
    </div>
  );
});

function EmptyState({ paused, hasFilter }: { paused: boolean; hasFilter: boolean }) {
  const message = !ipcAvailable
    ? "IPC unavailable. Launch through `npm run tauri dev` to attach the engine stream."
    : hasFilter
      ? "No events match the active filter."
      : paused
        ? "Capture paused. New events are counted but not buffered."
        : "Waiting for engine stream.";
  return <div className="flex h-full items-center justify-center text-xs text-fg-faint">{message}</div>;
}

export function toRow(event: TelemetryEvent): Row {
  const base = { key: String(event.seq), seq: event.seq, time: formatTimestamp(event.tsUs) };
  switch (event.kind) {
    case "engineHeartbeat":
      return {
        ...base,
        kind: "Heartbeat",
        kindTone: "muted",
        target: "engine",
        result: "-",
        resultTone: "muted",
        latency: "-",
        detail: `uptime ${formatUptime(event.uptimeMs)}  subs ${event.subscribers}`,
      };
    case "guardDecision":
      return {
        ...base,
        kind: "Guard",
        kindTone: event.verdict === "accepted" ? "ok" : "fault",
        target: event.input,
        result: event.verdict === "accepted" ? "accepted" : "rejected",
        resultTone: event.verdict === "accepted" ? "ok" : "fault",
        latency: "-",
        detail: event.code ?? (event.host !== null ? `host ${event.host}` : ""),
      };
    case "probeCompleted":
      return {
        ...base,
        kind: "Probe",
        kindTone: "muted",
        target: event.url,
        result: event.status === null ? "ERR" : `HEAD ${event.status}`,
        resultTone: event.status === null ? "warn" : httpStatusTone(event.status),
        latency: formatLatency(event.latencyUs),
        detail: event.error ?? "",
      };
    case "proxyStateChanged": {
      const { status } = event;
      return {
        ...base,
        kind: "Proxy",
        kindTone: "muted",
        target: status.listener ?? "listener",
        result: status.running ? "listening" : "stopped",
        resultTone: status.running ? "ok" : "muted",
        latency: "-",
        detail: [
          status.upstream === null ? null : `-> ${status.upstream}`,
          describeFaults(status.armed, status.profile),
          status.rules.length === 0 ? null : `${status.rules.length} route rule${status.rules.length === 1 ? "" : "s"}`,
        ]
          .filter((part) => part !== null)
          .join("  "),
      };
    }
    case "proxyExchange": {
      const drift = summarizeViolations(event.violations);
      const faulted = event.findings.some((finding) => finding.severity === "fault");
      const flagged = event.fault !== null || drift !== null || event.findings.length > 0;
      return {
        ...base,
        kind: "Proxy",
        kindTone: faulted ? "fault" : flagged ? "warn" : "muted",
        target: `${event.method} ${event.path}`,
        result: event.status === null ? "RST" : String(event.status),
        resultTone: event.status === null ? "fault" : httpStatusTone(event.status),
        latency: formatLatency(event.latencyUs),
        detail: [
          event.fault === "statusMutation" ? "injected status" : null,
          event.fault === "connectionDrop" ? "injected reset" : null,
          event.fault === "partialBodyDrop" ? `injected mid-body reset after ${formatBytes(event.responseBytes)}` : null,
          ...event.findings.map((finding) => `${AUDIT_SHORT[finding.kind]} ${finding.detail}`),
          drift === null ? null : `drift ${drift}`,
          event.rule === null ? null : `rule ${event.rule}`,
          event.injectedDelayUs > 0 ? `+${formatLatency(event.injectedDelayUs)} delay` : null,
          event.upstreamLatencyUs === null ? null : `upstream ${formatLatency(event.upstreamLatencyUs)}`,
          `req ${formatBytes(event.requestBytes)}`,
          `res ${formatBytes(event.responseBytes)}`,
          event.error,
        ]
          .filter((part) => part !== null)
          .join("  "),
      };
    }
    case "burstStarted":
      return {
        ...base,
        kind: "Burst",
        kindTone: "muted",
        target: event.target,
        result: `${event.method} x${event.workers}`,
        resultTone: "muted",
        latency: "-",
        detail: [
          `run ${event.id.slice(0, 8)}`,
          event.syncMode === "lastByte" ? "barrier armed, last byte held" : "barrier armed",
          event.idempotencyKey === null ? null : `idempotency-key ${event.idempotencyKey}`,
        ]
          .filter((part) => part !== null)
          .join("  "),
      };
    case "burstSample": {
      const { sample } = event;
      const drift = summarizeViolations(sample.violations);
      return {
        ...base,
        kind: "Burst",
        kindTone: drift === null ? "muted" : "warn",
        target: `worker ${sample.worker}`,
        result: sample.status === null ? "ERR" : String(sample.status),
        resultTone: sample.status === null ? "fault" : httpStatusTone(sample.status),
        latency: formatLatency(sample.latencyUs),
        detail:
          sample.error ??
          [
            drift === null ? null : `drift ${drift}`,
            sample.ttfbUs === null ? null : `ttfb ${formatLatency(sample.ttfbUs)}`,
            sample.dispatchOffsetUs === null ? null : `dispatch +${formatLatency(sample.dispatchOffsetUs)}`,
            formatBytes(sample.bytes),
            sample.bodyHash === null ? null : `#${sample.bodyHash.slice(0, 8)}`,
          ]
            .filter((part) => part !== null)
            .join("  "),
      };
    }
    case "burstCompleted":
      return {
        ...base,
        kind: "Burst",
        kindTone: event.anomalies > 0 ? "fault" : "ok",
        target: `run ${event.id.slice(0, 8)}`,
        result: event.anomalies > 0 ? `${event.anomalies} anomal${event.anomalies === 1 ? "y" : "ies"}` : "uniform",
        resultTone: event.anomalies > 0 ? "fault" : "ok",
        latency: formatLatency(event.wallUs),
        detail: `spread ${event.dispatchSpreadUs === null ? "-" : formatLatency(event.dispatchSpreadUs)} ${SYNC_LABEL[event.syncMode]}  errors ${event.errors}`,
      };
    case "routeScanCompleted":
      return {
        ...base,
        kind: "Scan",
        kindTone: "muted",
        target: event.root,
        result: `${event.routes} routes`,
        resultTone: event.truncated ? "warn" : event.routes > 0 ? "ok" : "muted",
        latency: formatLatency(event.elapsedUs),
        detail: [`${event.filesVisited} files`, event.truncated ? "truncated at cap" : null]
          .filter((part) => part !== null)
          .join("  "),
      };
    case "fuzzerStarted":
      return {
        ...base,
        kind: "Fuzzer",
        kindTone: "muted",
        target: event.target,
        result: `${event.method} x${event.cases}`,
        resultTone: "muted",
        latency: "-",
        detail: `run ${event.id.slice(0, 8)}  baseline first`,
      };
    case "fuzzerCaseCompleted": {
      const { result } = event;
      const tone: Tone = result.severity === "fault" ? "fault" : result.severity === "warn" ? "warn" : "muted";
      return {
        ...base,
        kind: "Fuzzer",
        kindTone: tone,
        target: `#${result.index} ${result.label}`,
        result: result.status === null ? fuzzVerdictLabel(result.verdict) : String(result.status),
        resultTone: result.status === null ? (result.verdict === "unreachable" ? "warn" : "fault") : httpStatusTone(result.status),
        latency: result.latencyUs === 0 ? "-" : formatLatency(result.latencyUs),
        detail:
          result.error ??
          [
            result.massAssignment === null ? null : result.massAssignment.detail,
            result.disclosure === null ? null : `leak ${DISCLOSURE_LABEL[result.disclosure.kind]}: ${result.disclosure.evidence}`,
            result.violations.length === 0 ? null : `drift ${summarizeViolations(result.violations) ?? ""}`,
            `req ${formatBytes(result.requestBytes)}`,
            `res ${formatBytes(result.responseBytes)}`,
          ]
            .filter((part) => part !== null)
            .join("  "),
      };
    }
    case "fuzzerCompleted":
      return {
        ...base,
        kind: "Fuzzer",
        kindTone: event.faults > 0 ? "fault" : event.warnings > 0 ? "warn" : "ok",
        target: `run ${event.id.slice(0, 8)}`,
        result: event.faults > 0 ? `${event.faults} fault${event.faults === 1 ? "" : "s"}` : event.aborted !== null ? "aborted" : "clean",
        resultTone: event.faults > 0 ? "fault" : event.aborted !== null ? "warn" : "ok",
        latency: formatLatency(event.wallUs),
        detail: [
          `${event.cases} cases`,
          `${event.warnings} warn`,
          `${event.disclosures} leaks`,
          event.violations > 0 ? `${event.violations} drift` : null,
          event.aborted,
        ]
          .filter((part) => part !== null)
          .join("  "),
      };
    case "labStateChanged": {
      const { status } = event;
      const { counters } = status;
      return {
        ...base,
        kind: "Lab",
        kindTone: "muted",
        target: status.listener ?? "target lab",
        result: status.running ? status.mode : "stopped",
        resultTone: status.running ? (status.mode === "hardened" ? "ok" : "warn") : "muted",
        latency: "-",
        detail: `coupon ${counters.granted}/${status.couponLimit}  redeemed ${counters.redeemed}  orders ${counters.orders}  req ${counters.requests}`,
      };
    }
    case "labExchange": {
      const raced = event.outcome.startsWith("granted past limit");
      return {
        ...base,
        kind: "Lab",
        kindTone: event.status >= 500 || raced ? "fault" : "muted",
        target: `${event.method} ${event.path}`,
        result: String(event.status),
        resultTone: raced ? "fault" : httpStatusTone(event.status),
        latency: formatLatency(event.latencyUs),
        detail: `${event.mode}  ${event.outcome}`,
      };
    }
  }
}

function fuzzVerdictLabel(verdict: FuzzVerdict): string {
  switch (verdict) {
    case "transportFailure":
      return "ABORT";
    case "unreachable":
      return "DOWN";
    case "skipped":
      return "SKIP";
    default:
      return "ERR";
  }
}

function describeFaults(armed: boolean, profile: FaultProfile): string {
  if (!armed) return "faults disarmed";
  const parts = [`latency ${profile.latencyMs}±${profile.jitterMs} ms`];
  if (profile.dropRate > 0) parts.push(`rst ${profile.dropRate}%`);
  if (profile.statusMutation !== "none") parts.push(`${profile.statusMutation} @ ${profile.mutationRate}%`);
  const partial = describePartialDrop(profile);
  if (partial !== null) parts.push(partial);
  return `armed: ${parts.join(", ")}`;
}
