import { Link2, Play, Power, RotateCcw, Square, X } from "lucide-react";
import type { BurstControl } from "../../hooks/useBurst";
import type { EngineLink } from "../../hooks/useEngineStatus";
import type { FuzzerControl } from "../../hooks/useFuzzer";
import type { GuardState } from "../../hooks/useGuardValidator";
import type { ProxyControl } from "../../hooks/useProxy";
import type { FuzzerProgress, TrafficAudit } from "../../hooks/useTelemetry";
import { contractFor } from "../../lib/contract";
import type { RequestOrigin } from "../../lib/request";
import { METHOD_BADGE, type RequestTarget } from "../../lib/routes";
import type { BurstPreset, FuzzPreset } from "../../lib/risk";
import { summarizeProfile } from "../../lib/rules";
import { AUDIT_KINDS, AUDIT_LABEL, type AuditKind } from "../../lib/traffic";
import type {
  DiscoveredRoute,
  FaultProfile,
  FaultRule,
  HeaderPair,
  RouteMethod,
  StatusMutation,
} from "../../lib/types";
import { Section, StatusDot, TabStrip, ToolButton } from "../shell/PanelHeader";
import { BurstPanel } from "./BurstPanel";
import { ErrorLine } from "./ErrorLine";
import { FuzzerPanel } from "./FuzzerPanel";
import { Slider } from "./Slider";

export const DEFAULT_FAULT_PROFILE: FaultProfile = {
  latencyMs: 0,
  jitterMs: 0,
  dropRate: 0,
  statusMutation: "none",
  mutationRate: 0,
  partialDropRate: 0,
  partialDropBytes: null,
};

/** Mirrors engine/fault.rs `MAX_PARTIAL_DROP_BYTES`. */
const MAX_PARTIAL_DROP_BYTES = 16 * 1024 * 1024;

const MUTATIONS: readonly StatusMutation[] = ["none", "429", "500", "502", "503", "504"];

export type ChaosTab = "faults" | "burst" | "fuzzer";

interface ChaosControlsProps {
  tab: ChaosTab;
  onTab: (tab: ChaosTab) => void;
  profile: FaultProfile;
  onChange: (profile: FaultProfile) => void;
  link: EngineLink;
  guard: GuardState;
  /** Where Burst and Fuzzer send requests: the validated target or the proxy listener. */
  requestOrigin: RequestOrigin | null;
  proxy: ProxyControl;
  /** Listener port; shared with the main toolbar's Start proxy command. */
  listenPort: number;
  onListenPort: (port: number) => void;
  burst: BurstControl;
  fuzzer: FuzzerControl;
  fuzzerProgress: FuzzerProgress | null;
  target: RequestTarget;
  onTarget: (target: RequestTarget) => void;
  burstBody: string;
  onBurstBody: (body: string) => void;
  /** Burst header lines; a replayed header case writes its override here. */
  burstHeaders: string;
  onBurstHeaders: (text: string) => void;
  fuzzPayload: string;
  onFuzzPayload: (payload: string) => void;
  /** OpenAPI sample of the selected route, offered by both payload fields. */
  sampleBody: string | null;
  route: DiscoveredRoute | null;
  /** Where the current burst body came from, when it was not typed: a replayed fuzz case. */
  burstOrigin: string | null;
  onReplayInBurst: (target: RequestTarget, body: string, origin: string, headers: HeaderPair[]) => void;
  /** Passive audit counters folded from proxied exchanges. */
  audit: TrafficAudit;
  /** Narrows the telemetry table to one audit category (`null`: every audited exchange). */
  onAuditFilter: (kind: AuditKind | null) => void;
  /**
   * Setup an auto-targeted route risk opens the Burst or Fuzzer tab with. A new `nonce`
   * remounts the panel, so the preset replaces whatever was configured.
   */
  preset: ChaosPreset | null;
}

export interface ChaosPreset {
  nonce: number;
  burst: BurstPreset | null;
  fuzz: FuzzPreset | null;
}

export function ChaosControls(props: ChaosControlsProps) {
  const { tab, onTab, link, guard, target, onTarget, sampleBody, route } = props;
  const online = link.state === "online";
  // A selected route binds with its own method (ANY stays method-agnostic); without one the
  // Burst/Fuzzer request target is the route being exercised.
  const ruleTarget: RuleTarget =
    route !== null
      ? { method: route.method === "ANY" ? null : route.method, path: route.path }
      : { method: target.method, path: target.path };

  return (
    <div className="flex h-full flex-col bg-bg">
      <TabStrip<ChaosTab>
        label="Tools"
        value={tab}
        onChange={onTab}
        tabs={[
          { id: "faults", label: "Faults" },
          { id: "burst", label: "Burst" },
          { id: "fuzzer", label: "Fuzzer" },
        ]}
      />
      {tab === "faults" && (
        <FaultsTab
          profile={props.profile}
          onChange={props.onChange}
          link={link}
          guard={guard}
          proxy={props.proxy}
          listenPort={props.listenPort}
          onListenPort={props.onListenPort}
          ruleTarget={ruleTarget}
          audit={props.audit}
          onAuditFilter={props.onAuditFilter}
        />
      )}
      {tab === "burst" && (
        <BurstPanel
          key={props.preset?.burst === null ? 0 : (props.preset?.nonce ?? 0)}
          preset={props.preset?.burst ?? null}
          requestOrigin={props.requestOrigin}
          burst={props.burst}
          online={online}
          target={target}
          onTarget={onTarget}
          body={props.burstBody}
          onBody={props.onBurstBody}
          headers={props.burstHeaders}
          onHeaders={props.onBurstHeaders}
          sampleBody={sampleBody}
          origin={props.burstOrigin}
          contract={contractFor(route, target.method, target.path)}
        />
      )}
      {tab === "fuzzer" && (
        <FuzzerPanel
          key={props.preset?.fuzz === null ? 0 : (props.preset?.nonce ?? 0)}
          preset={props.preset?.fuzz ?? null}
          requestOrigin={props.requestOrigin}
          fuzzer={props.fuzzer}
          progress={props.fuzzerProgress}
          online={online}
          target={target}
          onTarget={onTarget}
          payload={props.fuzzPayload}
          onPayload={props.onFuzzPayload}
          sampleBody={sampleBody}
          contract={contractFor(route, target.method, target.path)}
          onSendToBurst={props.onReplayInBurst}
        />
      )}
    </div>
  );
}

interface RuleTarget {
  method: RouteMethod | null;
  path: string;
}

interface FaultsTabProps {
  profile: FaultProfile;
  onChange: (profile: FaultProfile) => void;
  link: EngineLink;
  guard: GuardState;
  proxy: ProxyControl;
  listenPort: number;
  onListenPort: (port: number) => void;
  ruleTarget: RuleTarget;
  audit: TrafficAudit;
  onAuditFilter: (kind: AuditKind | null) => void;
}

function FaultsTab({
  profile,
  onChange,
  link,
  guard,
  proxy,
  listenPort,
  onListenPort: setListenPort,
  ruleTarget,
  audit,
  onAuditFilter,
}: FaultsTabProps) {
  const online = link.state === "online" && proxy.status !== null;
  const running = proxy.status?.running ?? false;
  const armed = proxy.status?.armed ?? false;
  const rules = proxy.status?.rules ?? [];
  const upstream = guard.phase === "accepted" ? guard.target.normalized : null;
  const set = <K extends keyof FaultProfile>(key: K, value: FaultProfile[K]) => onChange({ ...profile, [key]: value });

  return (
    <>
      {/* Wraps instead of truncating: below ~280px the controls move to a second line so the
          bound address stays readable. */}
      <div className="flex min-h-7 shrink-0 flex-wrap items-center gap-x-1.5 gap-y-1 border-b border-line px-2.5 py-[3px] text-xs">
        <div className="flex min-w-0 flex-1 basis-36 items-center gap-1.5">
          <StatusDot className={running ? "bg-ok" : "bg-muted"} />
          <span className="num truncate text-fg-dim">
            {running ? `listener ${proxy.status?.listener ?? "-"}` : "listener offline"}
          </span>
        </div>
        <div className="ml-auto flex shrink-0 items-center gap-1">
          <label className="flex h-5 items-center field pl-1.5">
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
        <span className="caption text-fg-faint">Upstream</span>
        <span className="num truncate text-fg" title={proxy.status?.upstream ?? upstream ?? undefined}>
          {proxy.status?.upstream ?? upstream ?? "no validated target"}
        </span>
        {(proxy.status?.contracts ?? 0) > 0 && (
          <span
            className="num ml-auto shrink-0 text-fg-faint"
            title="OpenAPI response contracts from the route list; forwarded responses are checked against them"
          >
            {proxy.status?.contracts} contracts
          </span>
        )}
      </div>

      {proxy.error !== null && <ErrorLine error={proxy.error} />}

      <div className="min-h-0 flex-1 overflow-y-auto">
        <TrafficAuditSection audit={audit} running={running} onFilter={onAuditFilter} />

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
          <div className="flex flex-col gap-1.5">
            <Slider label="RST" unit="%" min={0} max={100} step={1} value={profile.dropRate} onChange={(v) => set("dropRate", v)} />
            <Slider
              label="Mid-body"
              unit="%"
              min={0}
              max={100}
              step={1}
              value={profile.partialDropRate ?? 0}
              onChange={(v) => set("partialDropRate", v)}
            />
            <CutPointField
              value={profile.partialDropBytes ?? null}
              disabled={(profile.partialDropRate ?? 0) === 0}
              onChange={(v) => set("partialDropBytes", v)}
            />
          </div>
        </Section>

        <Section title="Status mutation">
          <div className="mb-2 grid grid-cols-6 overflow-hidden rounded-xs border border-line-strong">
            {MUTATIONS.map((m) => (
              <button
                key={m}
                type="button"
                onClick={() => set("statusMutation", m)}
                aria-pressed={profile.statusMutation === m}
                className={`num h-6 border-r border-line text-xs last:border-r-0 ${
                  profile.statusMutation === m ? "bg-select text-select-fg" : "bg-control text-fg hover:bg-active"
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

        <RouteRules
          rules={rules}
          target={ruleTarget}
          profile={profile}
          disabled={!online}
          onApply={proxy.applyRules}
        />

        <Section title="Engine profile" defaultOpen={false}>
          <pre className="num overflow-x-auto rounded-xs border border-line bg-field p-2 text-2xs leading-4 text-fg-dim">
            {proxy.status === null ? "engine unavailable" : JSON.stringify({ armed, ...proxy.status.profile }, null, 2)}
          </pre>
        </Section>
      </div>

      <div className="flex h-9 shrink-0 items-center gap-2 border-t border-line px-2.5">
        <StatusDot className={armed ? "bg-warn" : "bg-muted"} />
        <span className="min-w-0 truncate text-2xs text-fg-faint">
          {armed
            ? running
              ? rules.length > 0
                ? `Injecting; ${rules.length} route rule${rules.length === 1 ? "" : "s"} before the global profile`
                : "Injecting on every proxied request"
              : "Armed; starts injecting when the listener runs"
            : "Disarmed; traffic passes through"}
        </span>
        <button
          type="button"
          disabled={!online}
          aria-pressed={armed}
          onClick={() => proxy.applyFaults(!armed, profile)}
          className={`btn ml-auto ${
            armed
              ? "!border-warn/70 !bg-warn/15"
              : "btn-primary"
          }`}
        >
          <Power size={11} strokeWidth={1.75} />
          {armed ? "Disarm" : "Arm"}
        </button>
      </div>
    </>
  );
}

/** Bytes of the upstream body forwarded before the mid-body reset; empty cuts at half. */
function CutPointField({
  value,
  disabled,
  onChange,
}: {
  value: number | null;
  disabled: boolean;
  onChange: (value: number | null) => void;
}) {
  return (
    <div className={`flex h-5 items-center gap-2 text-xs ${disabled ? "opacity-40" : ""}`}>
      <span className="w-[52px] shrink-0 text-fg-dim">Cut at</span>
      <label className="flex h-5 w-[92px] shrink-0 items-center field pr-1.5">
        <input
          type="number"
          min={0}
          max={MAX_PARTIAL_DROP_BYTES}
          value={value ?? ""}
          placeholder="half"
          disabled={disabled}
          aria-label="Mid-body cut point in bytes"
          onChange={(e) => {
            const raw = e.target.value.trim();
            if (raw === "") return onChange(null);
            const next = Number(raw);
            if (Number.isInteger(next) && next >= 0 && next <= MAX_PARTIAL_DROP_BYTES) onChange(next);
          }}
          className="num w-full min-w-0 bg-transparent pl-1.5 text-right text-xs text-fg-bright outline-none placeholder:text-fg-faint [appearance:textfield] [&::-webkit-inner-spin-button]:appearance-none"
        />
        <span className="num pl-1 text-2xs text-fg-faint">B</span>
      </label>
      <span className="min-w-0 truncate text-2xs text-fg-faint" title="Full Content-Length in the head, body cut short, then SO_LINGER=0 reset">
        {value === null ? "head + half the body, then RST" : `head + ${value} B, then RST`}
      </span>
    </div>
  );
}

/** Live counters of the passive audit; a row opens the matching exchanges in telemetry. */
function TrafficAuditSection({
  audit,
  running,
  onFilter,
}: {
  audit: TrafficAudit;
  running: boolean;
  onFilter: (kind: AuditKind | null) => void;
}) {
  const total = AUDIT_KINDS.reduce((sum, kind) => sum + audit.counts[kind], 0);
  return (
    <Section
      title="Traffic audit"
      aside={
        <button
          type="button"
          onClick={() => onFilter(null)}
          disabled={total === 0}
          title="Show every audited exchange in telemetry"
          className="num text-2xs text-fg-faint hover:text-fg disabled:hover:text-fg-faint"
        >
          {audit.exchanges} exchanges
        </button>
      }
    >
      <div className="flex flex-col border-t border-line/60">
        {AUDIT_KINDS.map((kind) => {
          const count = audit.counts[kind];
          const tone = count === 0 ? "text-fg-faint" : kind === "passiveDisclosure" && audit.faults > 0 ? "text-fault" : "text-warn";
          return (
            <button
              key={kind}
              type="button"
              disabled={count === 0}
              onClick={() => onFilter(kind)}
              title={count === 0 ? AUDIT_LABEL[kind] : `Show ${AUDIT_LABEL[kind].toLowerCase()} findings in telemetry`}
              className="grid h-5 grid-cols-[minmax(0,1fr)_auto] items-center border-b border-line/60 text-left text-xs hover:bg-active disabled:cursor-default disabled:hover:bg-transparent"
            >
              <span className={`truncate ${count === 0 ? "text-fg-faint" : "text-fg-dim"}`}>{AUDIT_LABEL[kind]}</span>
              <span className={`num ${tone}`}>{count}</span>
            </button>
          );
        })}
      </div>
      <div className="pt-1 text-2xs text-fg-faint">
        {running
          ? "Every proxied exchange is checked; injected faults are excluded from response checks."
          : "Starts with the listener; findings attach to proxy exchanges in telemetry."}
      </div>
    </Section>
  );
}

function sameRoute(rule: FaultRule, target: RuleTarget): boolean {
  return rule.method === target.method && rule.pathPattern === target.path;
}

/** Rules bind a snapshot of the slider profile; re-binding the same route replaces it. */
function RouteRules({
  rules,
  target,
  profile,
  disabled,
  onApply,
}: {
  rules: readonly FaultRule[];
  target: RuleTarget;
  profile: FaultProfile;
  disabled: boolean;
  onApply: (rules: FaultRule[]) => void;
}) {
  const bound = rules.some((rule) => sameRoute(rule, target));
  const bind = () => {
    const rule: FaultRule = { method: target.method, pathPattern: target.path, profile };
    onApply(bound ? rules.map((r) => (sameRoute(r, target) ? rule : r)) : [...rules, rule]);
  };
  const label = `${target.method === null ? "ANY" : METHOD_BADGE[target.method]} ${target.path}`;

  return (
    <Section
      title="Route rules"
      aside={
        rules.length > 0 ? (
          <ToolButton label="Clear" disabled={disabled} onClick={() => onApply([])} />
        ) : (
          <span className="num text-2xs text-fg-faint">first match wins</span>
        )
      }
    >
      {rules.length > 0 && (
        <div className="mb-2 flex flex-col border-t border-line/60">
          {rules.map((rule, index) => (
            <div
              key={`${rule.method ?? "ANY"} ${rule.pathPattern}`}
              className="grid h-6 grid-cols-[14px_36px_minmax(0,1fr)_auto_18px] items-center gap-1.5 border-b border-line/60 text-xs"
            >
              <span className="num text-2xs text-fg-faint">{index + 1}</span>
              <span className="num border border-line text-center text-2xs leading-[14px] text-fg-dim">
                {rule.method === null ? "ANY" : METHOD_BADGE[rule.method]}
              </span>
              <span className="num truncate text-fg" title={rule.pathPattern}>
                {rule.pathPattern}
              </span>
              <span className="num text-2xs text-warn">{summarizeProfile(rule.profile)}</span>
              <button
                type="button"
                aria-label={`Remove rule ${index + 1}`}
                title="Remove rule"
                disabled={disabled}
                onClick={() => onApply(rules.filter((_, i) => i !== index))}
                className="flex size-[18px] items-center justify-center text-fg-faint hover:text-fg disabled:opacity-40"
              >
                <X size={11} strokeWidth={1.5} />
              </button>
            </div>
          ))}
        </div>
      )}
      <button
        type="button"
        disabled={disabled || target.path.trim() === ""}
        onClick={bind}
        title={`Bind ${summarizeProfile(profile)} to ${label}`}
        className="btn w-full min-w-0"
      >
        <Link2 size={11} strokeWidth={1.5} className="shrink-0" />
        <span className="shrink-0">{bound ? "Rebind" : "Bind"} profile to</span>
        <span className="num truncate text-fg">{label}</span>
      </button>
      <div className="pt-1 text-2xs text-fg-faint">
        Matched against the upstream path while armed; unmatched requests use the global profile.
      </div>
    </Section>
  );
}
