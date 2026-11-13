import { memo, useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { TelemetryStore } from "../../hooks/useTelemetry";
import { TELEMETRY_CAPACITY } from "../../hooks/useTelemetry";
import { formatLatency, formatTimestamp, formatUptime } from "../../lib/format";
import { ipcAvailable } from "../../lib/ipc";
import { httpStatusTone, TONE_TEXT, type Tone } from "../../lib/tone";
import type { TelemetryEvent } from "../../lib/types";
import { TelemetryToolbar, type KindFilter } from "./TelemetryToolbar";

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
    const source = filter === "all" ? store.events : store.events.filter((e) => e.kind === filter);
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
  }
}
