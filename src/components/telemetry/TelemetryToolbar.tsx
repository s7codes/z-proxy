import { Pause, Play, Trash2 } from "lucide-react";
import { formatCount } from "../../lib/format";
import type { TelemetryKind } from "../../lib/types";
import { ToolButton } from "../shell/PanelHeader";

export type KindFilter = "all" | TelemetryKind;

const FILTERS: ReadonlyArray<{ id: KindFilter; label: string }> = [
  { id: "all", label: "All" },
  { id: "guardDecision", label: "Guard" },
  { id: "probeCompleted", label: "Probe" },
  { id: "engineHeartbeat", label: "Heartbeat" },
];

interface TelemetryToolbarProps {
  filter: KindFilter;
  onFilter: (filter: KindFilter) => void;
  paused: boolean;
  onTogglePause: () => void;
  onClear: () => void;
  visible: number;
  buffered: number;
  received: number;
  capacity: number;
}

export function TelemetryToolbar(props: TelemetryToolbarProps) {
  return (
    <div className="flex h-7 shrink-0 items-center gap-2 border-b border-line bg-panel px-2.5">
      <span className="label-caps text-fg-dim">Telemetry</span>
      <div className="ml-2 flex items-center gap-0.5" role="radiogroup" aria-label="Event kind">
        {FILTERS.map((f) => (
          <ToolButton key={f.id} label={f.label} active={props.filter === f.id} onClick={() => props.onFilter(f.id)} />
        ))}
      </div>
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
