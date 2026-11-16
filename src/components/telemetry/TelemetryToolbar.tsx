import type { Ref } from "react";
import { Search, X } from "lucide-react";
import type { KindFilter, TelemetryFilter, TrafficAudit } from "../../hooks/useTelemetry";
import { formatCount } from "../../lib/format";
import { AUDIT_KINDS, AUDIT_LABEL, AUDIT_SHORT } from "../../lib/traffic";
import type { TelemetryKind } from "../../lib/types";

export type { KindFilter };

export const FILTER_KINDS: Record<Exclude<KindFilter, "all" | "findings">, ReadonlySet<TelemetryKind>> = {
  proxy: new Set<TelemetryKind>(["proxyExchange", "proxyStateChanged"]),
  burst: new Set<TelemetryKind>(["burstStarted", "burstSample", "burstCompleted"]),
  fuzzer: new Set<TelemetryKind>(["fuzzerStarted", "fuzzerCaseCompleted", "fuzzerCompleted"]),
  lab: new Set<TelemetryKind>(["labStateChanged", "labExchange"]),
  scan: new Set<TelemetryKind>(["routeScanCompleted"]),
  guard: new Set<TelemetryKind>(["guardDecision"]),
  probe: new Set<TelemetryKind>(["probeCompleted"]),
  heartbeat: new Set<TelemetryKind>(["engineHeartbeat"]),
};

const SEGMENTS: ReadonlyArray<{ id: KindFilter; label: string }> = [
  { id: "all", label: "All" },
  { id: "proxy", label: "Proxy" },
  { id: "burst", label: "Burst" },
  { id: "fuzzer", label: "Fuzzer" },
  { id: "lab", label: "Lab" },
];

const MORE: ReadonlyArray<{ id: KindFilter; label: string }> = [
  { id: "scan", label: "Scan" },
  { id: "guard", label: "Guard" },
  { id: "probe", label: "Probe" },
  { id: "heartbeat", label: "Heartbeat" },
];

interface TelemetryToolbarProps {
  filter: TelemetryFilter;
  onFilter: (filter: TelemetryFilter) => void;
  query: string;
  onQuery: (query: string) => void;
  queryRef: Ref<HTMLInputElement>;
  audit: TrafficAudit;
}

/** Filter row directly above the list: text match, source segments, audit categories. */
export function TelemetryToolbar({ filter, onFilter, query, onQuery, queryRef, audit }: TelemetryToolbarProps) {
  const total = AUDIT_KINDS.reduce((sum, kind) => sum + audit.counts[kind], 0);
  const findings = filter.kind === "findings";
  const moreActive = MORE.some((m) => m.id === filter.kind);

  return (
    <div className="flex h-[30px] shrink-0 items-center gap-2 border-b border-line bg-panel px-2">
      <label className="field flex h-[22px] w-56 min-w-32 shrink items-center gap-1.5 px-1.5">
        <Search size={12} strokeWidth={1.75} className="shrink-0 text-fg-faint" />
        <input
          ref={queryRef}
          value={query}
          onChange={(e) => onQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Escape") onQuery("");
          }}
          spellCheck={false}
          placeholder="Filter path, status, detail"
          aria-label="Filter events"
          className="num min-w-0 flex-1 bg-transparent text-xs outline-none"
        />
        {query !== "" && (
          <button type="button" aria-label="Clear filter" onClick={() => onQuery("")} className="text-fg-faint hover:text-fg">
            <X size={12} strokeWidth={1.75} />
          </button>
        )}
      </label>

      <div className="flex h-[22px] shrink-0 overflow-hidden rounded-xs border border-line-strong" role="radiogroup" aria-label="Event source">
        {SEGMENTS.map((s) => {
          const active = filter.kind === s.id;
          return (
            <button
              key={s.id}
              type="button"
              role="radio"
              aria-checked={active}
              onClick={() => onFilter({ kind: s.id, audit: null })}
              className={`border-r border-line-strong px-2 text-xs last:border-r-0 ${
                active ? "bg-select text-select-fg" : "bg-control text-fg hover:bg-active"
              }`}
            >
              {s.label}
            </button>
          );
        })}
      </div>
      <select
        value={moreActive ? filter.kind : ""}
        onChange={(e) => {
          const id = e.target.value as KindFilter | "";
          onFilter({ kind: id === "" ? "all" : id, audit: null });
        }}
        aria-label="Other event sources"
        className={`field h-[22px] shrink-0 px-1 text-xs ${moreActive ? "" : "text-fg-dim"}`}
      >
        <option value="">Other</option>
        {MORE.map((m) => (
          <option key={m.id} value={m.id}>
            {m.label}
          </option>
        ))}
      </select>

      <div className="h-4 w-px shrink-0 bg-line-strong" />

      <div className="flex min-w-0 items-center gap-1 overflow-hidden" role="radiogroup" aria-label="Audit findings">
        <button
          type="button"
          aria-pressed={findings && filter.audit === null}
          title={`${formatCount(audit.exchanges)} proxied exchanges audited`}
          onClick={() => onFilter(findings && filter.audit === null ? { kind: "all", audit: null } : { kind: "findings", audit: null })}
          className={`flex h-[22px] shrink-0 items-center gap-1.5 rounded-xs border px-1.5 text-xs ${
            findings && filter.audit === null
              ? "border-line-strong bg-active text-fg-bright"
              : "border-transparent text-fg-dim hover:bg-active hover:text-fg"
          }`}
        >
          Findings
          <span className={`num text-2xs ${total > 0 ? "text-warn" : "text-fg-faint"}`}>{formatCount(total)}</span>
        </button>
        {AUDIT_KINDS.filter((kind) => audit.counts[kind] > 0).map((kind) => {
          const active = findings && filter.audit === kind;
          return (
            <button
              key={kind}
              type="button"
              title={AUDIT_LABEL[kind]}
              aria-pressed={active}
              onClick={() => onFilter(active ? { kind: "findings", audit: null } : { kind: "findings", audit: kind })}
              className={`num flex h-[18px] shrink-0 items-center gap-1 rounded-xs border px-1.5 text-2xs ${
                active ? "border-warn bg-warn/15 text-fg-bright" : "border-line-strong text-fg-dim hover:bg-active"
              }`}
            >
              {AUDIT_SHORT[kind]}
              <span className="text-warn">{formatCount(audit.counts[kind])}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
