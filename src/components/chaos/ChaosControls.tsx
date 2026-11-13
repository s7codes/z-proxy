import { useId } from "react";
import { Power, RotateCcw } from "lucide-react";
import type { EngineLink } from "../../hooks/useEngineStatus";
import type { FaultProfile, StatusMutation } from "../../lib/types";
import { PanelHeader, Section, StatusSquare, ToolButton } from "../shell/PanelHeader";

export const DEFAULT_FAULT_PROFILE: FaultProfile = {
  latencyMs: 0,
  jitterMs: 0,
  dropRate: 0,
  statusMutation: "none",
  mutationRate: 0,
};

const MUTATIONS: readonly StatusMutation[] = ["none", "429", "500", "502", "503", "504"];

interface ChaosControlsProps {
  profile: FaultProfile;
  onChange: (profile: FaultProfile) => void;
  link: EngineLink;
}

export function ChaosControls({ profile, onChange, link }: ChaosControlsProps) {
  const listener = link.state === "online" ? link.status.proxyListener : null;
  const armable = listener !== null;
  const set = <K extends keyof FaultProfile>(key: K, value: FaultProfile[K]) =>
    onChange({ ...profile, [key]: value });

  return (
    <div className="flex h-full flex-col bg-panel">
      <PanelHeader title="Fault Injection">
        <ToolButton label="Reset" onClick={() => onChange(DEFAULT_FAULT_PROFILE)}>
          <RotateCcw size={11} strokeWidth={1.5} />
        </ToolButton>
      </PanelHeader>

      <div className="flex h-7 items-center gap-1.5 border-b border-line px-2.5 text-xs">
        <StatusSquare className={armable ? "bg-ok" : "bg-muted"} />
        <span className="num text-fg-dim">{armable ? `listener ${listener}` : "proxy listener offline"}</span>
        <span className="ml-auto text-2xs text-fg-faint">profile staged</span>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto">
        <Section title="Latency">
          <Slider label="Base" unit="ms" min={0} max={5000} step={10} value={profile.latencyMs} onChange={(v) => set("latencyMs", v)} />
          <Slider label="Jitter" unit="ms" min={0} max={2000} step={5} value={profile.jitterMs} onChange={(v) => set("jitterMs", v)} />
        </Section>

        <Section title="Transport">
          <Slider label="Drop" unit="%" min={0} max={100} step={1} value={profile.dropRate} onChange={(v) => set("dropRate", v)} />
        </Section>

        <Section title="Status Mutation">
          <div className="mb-2 grid grid-cols-6 border border-line">
            {MUTATIONS.map((m) => (
              <button
                key={m}
                type="button"
                onClick={() => set("statusMutation", m)}
                aria-pressed={profile.statusMutation === m}
                className={`num h-6 border-r border-line text-xs last:border-r-0 ${
                  profile.statusMutation === m ? "bg-active text-fg-bright" : "text-fg-dim hover:bg-active hover:text-fg"
                }`}
              >
                {m === "none" ? "off" : m}
              </button>
            ))}
          </div>
          <Slider
            label="Rate"
            unit="%"
            min={0}
            max={100}
            step={1}
            value={profile.mutationRate}
            disabled={profile.statusMutation === "none"}
            onChange={(v) => set("mutationRate", v)}
          />
        </Section>

        <Section title="Profile Payload">
          <pre className="num overflow-x-auto rounded-xs border border-line bg-bg p-2 text-2xs leading-4 text-fg-dim">
            {JSON.stringify(profile, null, 2)}
          </pre>
        </Section>
      </div>

      <div className="flex h-9 shrink-0 items-center gap-2 border-t border-line px-2.5">
        <span className="text-2xs text-fg-faint">{armable ? "Applies to all proxied routes" : "Requires a running proxy listener"}</span>
        <button
          type="button"
          disabled={!armable}
          className="ml-auto flex h-6 items-center gap-1.5 rounded-xs border border-line-strong bg-active px-2.5 text-xs font-medium text-fg-bright hover:border-fg-faint disabled:cursor-not-allowed disabled:border-line disabled:bg-transparent disabled:text-fg-faint"
        >
          <Power size={11} strokeWidth={1.75} />
          Arm
        </button>
      </div>
    </div>
  );
}

interface SliderProps {
  label: string;
  unit: string;
  min: number;
  max: number;
  step: number;
  value: number;
  disabled?: boolean;
  onChange: (value: number) => void;
}

function Slider({ label, unit, min, max, step, value, disabled = false, onChange }: SliderProps) {
  const id = useId();
  const commit = (raw: string) => {
    const parsed = Number(raw);
    if (Number.isFinite(parsed)) onChange(Math.min(max, Math.max(min, Math.round(parsed / step) * step)));
  };

  return (
    <div className={`grid grid-cols-[44px_1fr_72px] items-center gap-2 ${disabled ? "opacity-40" : ""}`}>
      <label htmlFor={id} className="text-xs text-fg-dim">
        {label}
      </label>
      <input
        id={id}
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        disabled={disabled}
        onChange={(e) => commit(e.target.value)}
      />
      <div className="flex h-5 items-center rounded-xs border border-line bg-bg pr-1.5 focus-within:border-fg-faint">
        <input
          type="number"
          min={min}
          max={max}
          step={step}
          value={value}
          disabled={disabled}
          aria-label={`${label} ${unit}`}
          onChange={(e) => commit(e.target.value)}
          className="num w-full min-w-0 bg-transparent pl-1.5 text-right text-xs text-fg-bright outline-none [appearance:textfield] [&::-webkit-inner-spin-button]:appearance-none"
        />
        <span className="num pl-1 text-2xs text-fg-faint">{unit}</span>
      </div>
    </div>
  );
}
