import { memo, useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { TelemetryStore } from "../../hooks/useTelemetry";
import { TELEMETRY_CAPACITY } from "../../hooks/useTelemetry";
import { DISCLOSURE_LABEL } from "../../lib/disclosure";
import { formatBytes, formatLatency, formatTimestamp, formatUptime } from "../../lib/format";
import { ipcAvailable } from "../../lib/ipc";
import { httpStatusTone, TONE_TEXT, type Tone } from "../../lib/tone";
import type { FaultProfile, FuzzVerdict, TelemetryEvent } from "../../lib/types";
import { FILTER_KINDS, TelemetryToolbar, type KindFilter } from "./TelemetryToolbar";

const ROW_HEIGHT = 22;
const GRID = "grid grid-cols-[72px_118px_92px_minmax(160px,1.4fr)_84px_88px_minmax(160px,1fr)]";

interface Row {
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

export function TelemetryTable({ store }: { store: TelemetryStore }) {
  const [filter, setFilter] = useState<KindFilter>("all");
  const scrollRef = useRef<HTMLDivElement>(null);
  const stickToBottom = useRef(true);

  const rows = useMemo(() => {
    const kinds = filter === "all" ? null : FILTER_KINDS[filter];
    const source = kinds === null ? store.events : store.events.filter((e) => kinds.has(e.kind));
    return source.map(toRow);
  }, [store.events, filter]);

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

  return (
    <div className="flex h-full flex-col bg-bg">
      <TelemetryToolbar
        filter={filter}
        onFilter={setFilter}
        paused={store.paused}
        onTogglePause={() => store.setPaused(!store.paused)}
        onClear={store.clear}
        visible={rows.length}
        buffered={store.events.length}
        received={store.totalReceived}
        capacity={TELEMETRY_CAPACITY}
      />
      <div className={`${GRID} h-6 shrink-0 items-center border-b border-line bg-panel px-2.5 label-caps text-fg-faint`}>
        <span className="pr-3 text-right">Seq</span>
        <span>Time</span>
        <span>Kind</span>
        <span>Target</span>
        <span>Result</span>
        <span className="pr-3 text-right">Latency</span>
        <span>Detail</span>
      </div>
      <div
        ref={scrollRef}
        className="relative min-h-0 flex-1 overflow-auto"
        onScroll={(e) => {
          const el = e.currentTarget;
          stickToBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < ROW_HEIGHT * 2;
        }}
      >
        {rows.length === 0 ? (
          <EmptyState paused={store.paused} hasFilter={filter !== "all" && store.events.length > 0} />
        ) : (
          <div style={{ height: virtualizer.getTotalSize() }} className="relative w-full">
            {virtualizer.getVirtualItems().map((item) => {
              const row = rows[item.index];
              if (row === undefined) return null;
              return <TableRow key={row.key} row={row} top={item.start} />;
            })}
          </div>
        )}
      </div>
    </div>
  );
}

const TableRow = memo(function TableRow({ row, top }: { row: Row; top: number }) {
  return (
    <div
      className={`${GRID} num absolute left-0 w-full items-center border-b border-line/50 px-2.5 text-xs hover:bg-active`}
      style={{ height: ROW_HEIGHT, transform: `translateY(${top}px)` }}
    >
      <span className="truncate pr-3 text-right text-fg-faint">{row.seq}</span>
      <span className="truncate text-fg-dim">{row.time}</span>
      <span className={`truncate ${TONE_TEXT[row.kindTone]}`}>{row.kind}</span>
      <span className="truncate pr-3 text-fg" title={row.target}>
        {row.target}
      </span>
      <span className={`truncate ${TONE_TEXT[row.resultTone]}`}>{row.result}</span>
      <span className="truncate pr-3 text-right text-fg-dim">{row.latency}</span>
      <span className="truncate text-fg-faint" title={row.detail}>
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
        ? "Stream paused. New events are counted but not buffered."
        : "Waiting for engine stream.";
  return <div className="flex h-full items-center justify-center text-xs text-fg-faint">{message}</div>;
}

function toRow(event: TelemetryEvent): Row {
  const base = { key: String(event.seq), seq: event.seq, time: formatTimestamp(event.tsUs) };
  switch (event.kind) {
    case "engineHeartbeat":
      return {
        ...base,
        kind: "HEARTBEAT",
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
        kind: "GUARD",
        kindTone: event.verdict === "accepted" ? "ok" : "fault",
        target: event.input,
        result: event.verdict === "accepted" ? "ACCEPT" : "REJECT",
        resultTone: event.verdict === "accepted" ? "ok" : "fault",
        latency: "-",
        detail: event.code ?? (event.host !== null ? `host ${event.host}` : ""),
      };
    case "probeCompleted":
      return {
        ...base,
        kind: "PROBE",
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
        kind: "PROXY",
        kindTone: "muted",
        target: status.listener ?? "listener",
        result: status.running ? "LISTEN" : "STOPPED",
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
    case "proxyExchange":
      return {
        ...base,
        kind: "PROXY",
        kindTone: event.fault === null ? "muted" : "warn",
        target: `${event.method} ${event.path}`,
        result: event.status === null ? "RST" : String(event.status),
        resultTone: event.status === null ? "fault" : httpStatusTone(event.status),
        latency: formatLatency(event.latencyUs),
        detail: [
          event.fault === "statusMutation" ? "injected status" : null,
          event.fault === "connectionDrop" ? "injected reset" : null,
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
    case "burstStarted":
      return {
        ...base,
        kind: "BURST",
        kindTone: "muted",
        target: event.target,
        result: `${event.method} x${event.workers}`,
        resultTone: "muted",
        latency: "-",
        detail: `run ${event.id.slice(0, 8)}  barrier armed`,
      };
    case "burstSample": {
      const { sample } = event;
      return {
        ...base,
        kind: "BURST",
        kindTone: "muted",
        target: `worker ${sample.worker}`,
        result: sample.status === null ? "ERR" : String(sample.status),
        resultTone: sample.status === null ? "fault" : httpStatusTone(sample.status),
        latency: formatLatency(sample.latencyUs),
        detail:
          sample.error ??
          [
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
        kind: "BURST",
        kindTone: event.anomalies > 0 ? "fault" : "ok",
        target: `run ${event.id.slice(0, 8)}`,
        result: event.anomalies > 0 ? `${event.anomalies} ANOMALY` : "UNIFORM",
        resultTone: event.anomalies > 0 ? "fault" : "ok",
        latency: formatLatency(event.wallUs),
        detail: `spread ${event.dispatchSpreadUs === null ? "-" : formatLatency(event.dispatchSpreadUs)}  errors ${event.errors}`,
      };
    case "routeScanCompleted":
      return {
        ...base,
        kind: "SCAN",
        kindTone: "muted",
        target: event.root,
        result: `${event.routes} ROUTES`,
        resultTone: event.truncated ? "warn" : event.routes > 0 ? "ok" : "muted",
        latency: formatLatency(event.elapsedUs),
        detail: [`${event.filesVisited} files`, event.truncated ? "truncated at cap" : null]
          .filter((part) => part !== null)
          .join("  "),
      };
    case "fuzzerStarted":
      return {
        ...base,
        kind: "FUZZ",
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
        kind: "FUZZ",
        kindTone: tone,
        target: `#${result.index} ${result.label}`,
        result: result.status === null ? fuzzVerdictLabel(result.verdict) : String(result.status),
        resultTone: result.status === null ? (result.verdict === "unreachable" ? "warn" : "fault") : httpStatusTone(result.status),
        latency: result.latencyUs === 0 ? "-" : formatLatency(result.latencyUs),
        detail:
          result.error ??
          [
            result.disclosure === null ? null : `leak ${DISCLOSURE_LABEL[result.disclosure.kind]}: ${result.disclosure.evidence}`,
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
        kind: "FUZZ",
        kindTone: event.faults > 0 ? "fault" : event.warnings > 0 ? "warn" : "ok",
        target: `run ${event.id.slice(0, 8)}`,
        result: event.faults > 0 ? `${event.faults} FAULT` : event.aborted !== null ? "ABORTED" : "CLEAN",
        resultTone: event.faults > 0 ? "fault" : event.aborted !== null ? "warn" : "ok",
        latency: formatLatency(event.wallUs),
        detail: [`${event.cases} cases`, `${event.warnings} warn`, `${event.disclosures} leaks`, event.aborted]
          .filter((part) => part !== null)
          .join("  "),
      };
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
  return `armed: ${parts.join(", ")}`;
}
