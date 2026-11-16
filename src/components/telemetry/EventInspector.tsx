import type { ReactNode } from "react";
import { formatBytes, formatLatency, formatTimestamp } from "../../lib/format";
import { TONE_TEXT } from "../../lib/tone";
import type { TelemetryEvent } from "../../lib/types";
import { toRow } from "./TelemetryTable";

type Scalar = string | number | boolean | null;

interface Field {
  key: string;
  value: Scalar;
}

interface ListField {
  key: string;
  items: readonly unknown[];
}

const MAX_DEPTH = 3;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Dotted-path scalars and arrays of an event, in declaration order. */
function flatten(value: Record<string, unknown>, prefix: string, depth: number, fields: Field[], lists: ListField[]) {
  for (const [name, child] of Object.entries(value)) {
    const key = prefix === "" ? name : `${prefix}.${name}`;
    if (Array.isArray(child)) {
      lists.push({ key, items: child });
    } else if (isRecord(child)) {
      if (depth < MAX_DEPTH) flatten(child, key, depth + 1, fields, lists);
    } else if (child === null || typeof child === "string" || typeof child === "number" || typeof child === "boolean") {
      fields.push({ key, value: child });
    }
  }
}

function renderValue(key: string, value: Scalar): ReactNode {
  if (value === null) return <span className="text-fg-faint">null</span>;
  if (typeof value === "boolean") return <span className="text-fg">{String(value)}</span>;
  if (typeof value === "number") {
    const leaf = key.slice(key.lastIndexOf(".") + 1);
    if (leaf === "tsUs") return formatTimestamp(value);
    if (leaf.endsWith("Us")) return `${formatLatency(value)}`;
    if (leaf.endsWith("Bytes") || leaf === "bytes") return `${formatBytes(value)}`;
    return value;
  }
  return value;
}

export function EventInspector({ event }: { event: TelemetryEvent | null }) {
  if (event === null) {
    return (
      <div className="flex h-full items-center justify-center bg-bg text-xs text-fg-faint">
        Select an event in the list. Arrow keys move the selection.
      </div>
    );
  }
  const row = toRow(event);
  const fields: Field[] = [];
  const lists: ListField[] = [];
  flatten(event as unknown as Record<string, unknown>, "", 0, fields, lists);
  const timing = timingOf(event);

  return (
    <div className="h-full overflow-auto bg-bg">
      <div className="flex min-h-[30px] items-center gap-3 border-b border-line px-3 py-1">
        <span className="text-sm font-semibold text-fg-bright">{row.kind}</span>
        <span className="num min-w-0 truncate text-sm text-fg select-text" title={row.target}>
          {row.target}
        </span>
        <span className={`num shrink-0 text-sm ${TONE_TEXT[row.resultTone]}`}>{row.result}</span>
        <span className="num ml-auto shrink-0 text-2xs text-fg-faint">
          #{row.seq} {row.time}
        </span>
      </div>

      {timing !== null && <TimingTable rows={timing} />}

      <table className="num w-full table-fixed border-collapse text-xs select-text">
        <colgroup>
          <col className="w-[34%] max-w-64" />
          <col />
        </colgroup>
        <tbody>
          {fields.map((field, index) => (
            <tr key={field.key} className={index % 2 === 1 ? "bg-zebra" : ""}>
              <td className="truncate py-0.5 pr-2 pl-3 align-top text-fg-dim" title={field.key}>
                {field.key}
              </td>
              <td className="py-0.5 pr-3 break-all text-fg-bright">{renderValue(field.key, field.value)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {lists.map((list) => (
        <div key={list.key} className="border-t border-line">
          <div className="flex h-6 items-center gap-2 px-3">
            <span className="caption text-fg">{list.key}</span>
            <span className="num text-2xs text-fg-faint">{list.items.length}</span>
          </div>
          {list.items.length === 0 ? (
            <div className="px-3 pb-2 text-xs text-fg-faint">empty</div>
          ) : (
            <pre className="num mx-3 mb-2 overflow-x-auto rounded-xs border border-line bg-field p-2 text-2xs leading-4 text-fg select-text">
              {list.items.map((item) => JSON.stringify(item)).join("\n")}
            </pre>
          )}
        </div>
      ))}
    </div>
  );
}

export function EventRaw({ event }: { event: TelemetryEvent | null }) {
  if (event === null) {
    return <div className="flex h-full items-center justify-center bg-bg text-xs text-fg-faint">No event selected.</div>;
  }
  return (
    <pre className="num h-full overflow-auto bg-bg px-3 py-2 text-xs leading-[18px] text-fg select-text">
      {JSON.stringify(event, null, 2)}
    </pre>
  );
}

interface Phase {
  label: string;
  startUs: number;
  durationUs: number;
}

/**
 * Phases on a shared axis from request start. Only events that carry a breakdown get one:
 * proxy exchanges (injected delay, then upstream) and burst samples (dispatch, TTFB, body).
 */
function timingOf(event: TelemetryEvent): Phase[] | null {
  if (event.kind === "proxyExchange") {
    const phases: Phase[] = [];
    if (event.injectedDelayUs > 0) phases.push({ label: "Injected delay", startUs: 0, durationUs: event.injectedDelayUs });
    if (event.upstreamLatencyUs !== null) {
      phases.push({ label: "Upstream exchange", startUs: event.injectedDelayUs, durationUs: event.upstreamLatencyUs });
    }
    phases.push({ label: "Total", startUs: 0, durationUs: event.latencyUs });
    return phases;
  }
  if (event.kind === "burstSample") {
    const { sample } = event;
    const offset = sample.dispatchOffsetUs ?? 0;
    const phases: Phase[] = [];
    if (sample.dispatchOffsetUs !== null) phases.push({ label: "Dispatch offset", startUs: 0, durationUs: offset });
    if (sample.ttfbUs !== null) {
      phases.push({ label: "Waiting (TTFB)", startUs: offset, durationUs: sample.ttfbUs });
      phases.push({
        label: "Content download",
        startUs: offset + sample.ttfbUs,
        durationUs: Math.max(0, sample.latencyUs - sample.ttfbUs),
      });
    }
    phases.push({ label: "Total", startUs: offset, durationUs: sample.latencyUs });
    return phases;
  }
  return null;
}

function TimingTable({ rows }: { rows: Phase[] }) {
  const span = Math.max(1, ...rows.map((r) => r.startUs + r.durationUs));
  return (
    <div className="border-b border-line px-3 py-2">
      <div className="caption mb-1 text-fg">Timing</div>
      <div className="flex flex-col gap-0.5">
        {rows.map((phase) => (
          <div key={phase.label} className="grid grid-cols-[132px_minmax(0,1fr)_84px] items-center gap-2 text-xs">
            <span className={phase.label === "Total" ? "font-semibold text-fg" : "text-fg-dim"}>{phase.label}</span>
            <div className="relative h-2.5 bg-zebra">
              <div
                className={`absolute inset-y-0 ${phase.label === "Total" ? "bg-fg-faint" : phase.label === "Injected delay" ? "bg-warn" : "bg-accent"}`}
                style={{
                  left: `${(phase.startUs / span) * 100}%`,
                  width: `max(1px, ${(phase.durationUs / span) * 100}%)`,
                }}
              />
            </div>
            <span className="num text-right text-fg">{formatLatency(phase.durationUs)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
