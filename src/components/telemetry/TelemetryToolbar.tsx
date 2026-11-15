import { Pause, Play, Trash2 } from "lucide-react";
import type { KindFilter, TelemetryFilter, TrafficAudit } from "../../hooks/useTelemetry";
import { formatCount } from "../../lib/format";
import { AUDIT_KINDS, AUDIT_LABEL, AUDIT_SHORT } from "../../lib/traffic";
import type { TelemetryKind } from "../../lib/types";
import { ToolButton } from "../shell/PanelHeader";

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

const FILTERS: ReadonlyArray<{ id: KindFilter; label: string }> = [
  { id: "all", label: "All" },
  { id: "proxy", label: "Proxy" },
  { id: "burst", label: "Burst" },
  { id: "fuzzer", label: "Fuzzer" },
  { id: "lab", label: "Lab" },
  { id: "scan", label: "Scan" },
  { id: "guard", label: "Guard" },
  { id: "probe", label: "Probe" },
  { id: "heartbeat", label: "Heartbeat" },
];

interface TelemetryToolbarProps {
  filter: TelemetryFilter;
  onFilter: (filter: TelemetryFilter) => void;
  audit: TrafficAudit;
  paused: boolean;
  onTogglePause: () => void;
  onClear: () => void;
  visible: number;
  buffered: number;
  received: number;
  capacity: number;
}

/** Live per-category counters of the passive audit; each narrows the table to its exchanges. */
function AuditBadges({
  audit,
  filter,
  onFilter,
}: {
  audit: TrafficAudit;
  filter: TelemetryFilter;
  onFilter: (filter: TelemetryFilter) => void;
}) {
  const total = AUDIT_KINDS.reduce((sum, kind) => sum + audit.counts[kind], 0);
  const findings = filter.kind === "findings";
  return (
    <>
      <div className="mx-1 h-3.5 w-px bg-line" />
      <div className="flex items-center gap-0.5" role="radiogroup" aria-label="Audit findings">
        <ToolButton
          label={`Findings ${formatCount(total)}`}
          active={findings && filter.audit === null}
          title={`${formatCount(audit.exchanges)} proxied exchanges audited`}
          onClick={() => onFilter({ kind: "findings", audit: null })}
        />
        {AUDIT_KINDS.filter((kind) => audit.counts[kind] > 0).map((kind) => (
          <button
            key={kind}
            type="button"
            title={AUDIT_LABEL[kind]}
            aria-pressed={findings && filter.audit === kind}
            onClick={() => onFilter(findings && filter.audit === kind ? { kind: "findings", audit: null } : { kind: "findings", audit: kind })}
            className={`num flex h-5 items-center gap-1 rounded-xs border px-1.5 text-2xs ${
              findings && filter.audit === kind
                ? "border-warn/60 bg-warn/10 text-warn"
                : "border-line text-fg-dim hover:border-line-strong hover:text-fg"
            }`}
          >
            {AUDIT_SHORT[kind]}
            <span className="text-fg-bright">{formatCount(audit.counts[kind])}</span>
          </button>
        ))}
      </div>
    </>
  );
}

export function TelemetryToolbar(props: TelemetryToolbarProps) {
  return (
    <div className="flex h-7 shrink-0 items-center gap-2 border-b border-line bg-panel px-2.5">
      <span className="label-caps text-fg-dim">Telemetry</span>
      <div className="ml-2 flex items-center gap-0.5" role="radiogroup" aria-label="Event kind">
        {FILTERS.map((f) => (
          <ToolButton
            key={f.id}
            label={f.label}
            active={props.filter.kind === f.id}
            onClick={() => props.onFilter({ kind: f.id, audit: null })}
          />
        ))}
      </div>
      <AuditBadges audit={props.audit} filter={props.filter} onFilter={props.onFilter} />
      <div className="mx-1 h-3.5 w-px bg-line" />
      <ToolButton label={props.paused ? "Resume" : "Pause"} active={props.paused} onClick={props.onTogglePause}>
        {props.paused ? <Play size={11} strokeWidth={1.5} /> : <Pause size={11} strokeWidth={1.5} />}
      </ToolButton>
      <ToolButton label="Clear" onClick={props.onClear}>
        <Trash2 size={11} strokeWidth={1.5} />
      </ToolButton>
      <div className="num ml-auto flex items-center gap-3 text-2xs text-fg-faint">
        <span>
          <span className="text-fg-dim">{formatCount(props.visible)}</span> shown
        </span>
        <span>
          <span className="text-fg-dim">{formatCount(props.buffered)}</span> / {formatCount(props.capacity)} buffered
        </span>
        <span>
          <span className="text-fg-dim">{formatCount(props.received)}</span> rx
        </span>
      </div>
    </div>
  );
}
