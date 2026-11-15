import { useState } from "react";
import { Play, Power, RotateCcw, Square } from "lucide-react";
import type { BurstControl } from "../../hooks/useBurst";
import type { EngineLink } from "../../hooks/useEngineStatus";
import type { GuardState } from "../../hooks/useGuardValidator";
import type { ProxyControl } from "../../hooks/useProxy";
import type { RequestTarget } from "../../lib/routes";
import type { FaultProfile, StatusMutation } from "../../lib/types";
import { PanelHeader, Section, StatusSquare, ToolButton } from "../shell/PanelHeader";
import { BurstPanel } from "./BurstPanel";
import { ErrorLine } from "./ErrorLine";
import { Slider } from "./Slider";

export const DEFAULT_FAULT_PROFILE: FaultProfile = {
  latencyMs: 0,
  jitterMs: 0,
  dropRate: 0,
  statusMutation: "none",
  mutationRate: 0,
};

const DEFAULT_LISTEN_PORT = 8787;
const MUTATIONS: readonly StatusMutation[] = ["none", "429", "500", "502", "503", "504"];

type ChaosTab = "faults" | "burst";

interface ChaosControlsProps {
  profile: FaultProfile;
  onChange: (profile: FaultProfile) => void;
  link: EngineLink;
  guard: GuardState;
  proxy: ProxyControl;
  burst: BurstControl;
  target: RequestTarget;
  onTarget: (target: RequestTarget) => void;
}

export function ChaosControls({ profile, onChange, link, guard, proxy, burst, target, onTarget }: ChaosControlsProps) {
  const [tab, setTab] = useState<ChaosTab>("faults");

  return (
    <div className="flex h-full flex-col bg-panel">
      <PanelHeader title="Chaos">
        <ToolButton label="Faults" active={tab === "faults"} onClick={() => setTab("faults")} />
        <ToolButton label="Burst" active={tab === "burst"} onClick={() => setTab("burst")} />
      </PanelHeader>
      {tab === "faults" ? (
        <FaultsTab profile={profile} onChange={onChange} link={link} guard={guard} proxy={proxy} />
      ) : (
        <BurstPanel guard={guard} burst={burst} online={link.state === "online"} target={target} onTarget={onTarget} />
      )}
    </div>
  );
}

interface FaultsTabProps {
  profile: FaultProfile;
  onChange: (profile: FaultProfile) => void;
  link: EngineLink;
  guard: GuardState;
  proxy: ProxyControl;
}

function FaultsTab({ profile, onChange, link, guard, proxy }: FaultsTabProps) {
  const [listenPort, setListenPort] = useState(DEFAULT_LISTEN_PORT);
  const online = link.state === "online" && proxy.status !== null;
  const running = proxy.status?.running ?? false;
  const armed = proxy.status?.armed ?? false;
  const upstream = guard.phase === "accepted" ? guard.target.normalized : null;
  const set = <K extends keyof FaultProfile>(key: K, value: FaultProfile[K]) => onChange({ ...profile, [key]: value });

  return (
    <>
      {/* Wraps instead of truncating: below ~280px the controls move to a second line so the
          bound address stays readable. */}
      <div className="flex min-h-7 shrink-0 flex-wrap items-center gap-x-1.5 gap-y-1 border-b border-line px-2.5 py-[3px] text-xs">
        <div className="flex min-w-0 flex-1 basis-36 items-center gap-1.5">
          <StatusSquare className={running ? "bg-ok" : "bg-muted"} />
          <span className="num truncate text-fg-dim">
            {running ? `listener ${proxy.status?.listener ?? "-"}` : "listener offline"}
          </span>
        </div>
        <div className="ml-auto flex shrink-0 items-center gap-1">
          <label className="flex h-5 items-center rounded-xs border border-line bg-bg pl-1.5 focus-within:border-fg-faint">
            <span className="text-2xs text-fg-faint">port</span>
            <input
              type="number"
              min={0}
              max={65535}
              value={listenPort}
              disabled={running}
              aria-label="Listener port"
              onChange={(e) => {
                const value = Number(e.target.value);
                if (Number.isInteger(value) && value >= 0 && value <= 65535) setListenPort(value);
              }}
              className="num w-12 bg-transparent px-1 text-right text-xs text-fg-bright outline-none disabled:text-fg-faint [appearance:textfield] [&::-webkit-inner-spin-button]:appearance-none"
            />
          </label>
          {running ? (
            <ToolButton label="Stop" disabled={proxy.busy} onClick={proxy.stop}>
              <Square size={10} strokeWidth={1.75} />
            </ToolButton>
          ) : (
            <ToolButton
              label="Start"
              disabled={!online || upstream === null || proxy.busy}
              title={upstream === null ? "Validate a loopback target in the inspector first" : `Proxy to ${upstream}`}
              onClick={() => upstream !== null && proxy.start(upstream, listenPort)}
            >
              <Play size={10} strokeWidth={1.75} />
            </ToolButton>
          )}
        </div>
      </div>

      <div className="flex h-6 shrink-0 items-center gap-2 border-b border-line px-2.5 text-2xs">
        <span className="label-caps text-fg-faint">Upstream</span>
        <span className="num truncate text-fg" title={proxy.status?.upstream ?? upstream ?? undefined}>
          {proxy.status?.upstream ?? upstream ?? "no validated target"}
        </span>
      </div>

      {proxy.error !== null && <ErrorLine error={proxy.error} />}

      <div className="min-h-0 flex-1 overflow-y-auto">
        <Section
          title="Latency"
          aside={
            <ToolButton label="Reset" onClick={() => onChange(DEFAULT_FAULT_PROFILE)}>
              <RotateCcw size={10} strokeWidth={1.5} />
            </ToolButton>
          }
        >
          <div className="flex flex-col gap-1.5">
            <Slider label="Base" unit="ms" min={0} max={30000} step={10} value={profile.latencyMs} onChange={(v) => set("latencyMs", v)} />
            <Slider label="Jitter" unit="ms" min={0} max={10000} step={5} value={profile.jitterMs} onChange={(v) => set("jitterMs", v)} />
          </div>
        </Section>

        <Section title="Transport">
          <Slider label="RST" unit="%" min={0} max={100} step={1} value={profile.dropRate} onChange={(v) => set("dropRate", v)} />
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

        <Section title="Engine Profile">
          <pre className="num overflow-x-auto rounded-xs border border-line bg-bg p-2 text-2xs leading-4 text-fg-dim">
            {proxy.status === null ? "engine unavailable" : JSON.stringify({ armed, ...proxy.status.profile }, null, 2)}
          </pre>
        </Section>
      </div>

      <div className="flex h-9 shrink-0 items-center gap-2 border-t border-line px-2.5">
        <StatusSquare className={armed ? "bg-warn" : "bg-muted"} />
        <span className="text-2xs text-fg-faint">
          {armed ? (running ? "Injecting on every proxied request" : "Armed; starts injecting when the listener runs") : "Disarmed; traffic passes through"}
        </span>
        <button
          type="button"
          disabled={!online}
          aria-pressed={armed}
          onClick={() => proxy.applyFaults(!armed, profile)}
          className={`ml-auto flex h-6 items-center gap-1.5 rounded-xs border px-2.5 text-xs font-medium disabled:cursor-not-allowed disabled:border-line disabled:bg-transparent disabled:text-fg-faint ${
            armed
              ? "border-warn/60 bg-warn/10 text-warn hover:border-warn"
              : "border-line-strong bg-active text-fg-bright hover:border-fg-faint"
          }`}
        >
          <Power size={11} strokeWidth={1.75} />
          {armed ? "Disarm" : "Arm"}
        </button>
      </div>
    </>
  );
}
