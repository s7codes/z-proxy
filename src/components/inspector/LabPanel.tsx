import { Crosshair, Play, RotateCcw, Square, Waypoints } from "lucide-react";
import { DEFAULT_LISTEN_PORT } from "../../lib/rules";
import type { LabControl } from "../../hooks/useLab";
import type { Tone } from "../../lib/tone";
import { TONE_BG, TONE_TEXT } from "../../lib/tone";
import type { LabMode } from "../../lib/types";
import { ErrorLine } from "../chaos/ErrorLine";
import { StatusSquare, ToolButton } from "../shell/PanelHeader";

const MODES: ReadonlyArray<{ id: LabMode; label: string; tone: Tone; title: string }> = [
  {
    id: "unprotected",
    label: "Unprotected",
    tone: "warn",
    title: "Check-then-act coupon redemption; unvalidated checkout input leaks stack traces",
  },
  {
    id: "hardened",
    label: "Hardened",
    tone: "ok",
    title: "Conditional-update redemption; invalid checkout input is rejected with 422",
  },
];

export const LAB_MODE_TONE: Record<LabMode, Tone> = { unprotected: "warn", hardened: "ok" };

/** Whether Burst and Fuzzer traffic reaches the lab through the proxy listener. */
export interface LabRouting {
  /** The proxy runs with the lab as upstream and the panels send to its listener. */
  active: boolean;
  listener: string | null;
  armed: boolean;
  rules: number;
  busy: boolean;
}

interface LabPanelProps {
  lab: LabControl;
  online: boolean;
  onLoadTarget: () => void;
  routing: LabRouting;
  onRouteViaProxy: () => void;
  onRouteDirect: () => void;
}

/** Start/stop, defect mode and live counters of the embedded target lab. */
export function LabPanel({ lab, online, onLoadTarget, routing, onRouteViaProxy, onRouteDirect }: LabPanelProps) {
  const { status } = lab;
  const running = status?.running ?? false;
  const mode = status?.mode ?? "unprotected";
  const counters = lab.counters ?? status?.counters ?? null;
  const limit = status?.couponLimit ?? 1;
  const overRedeemed = counters !== null && counters.granted > limit;
  const controllable = online && status !== null;

  return (
    <div className="flex flex-col">
      <div className="flex h-6 items-center gap-1.5 text-xs">
        <StatusSquare className={running ? "bg-ok" : "bg-muted"} />
        <span className="num min-w-0 truncate text-fg-dim" title={status?.baseUrl ?? undefined}>
          {running ? (status?.listener ?? "-") : "lab offline"}
        </span>
        <div className="ml-auto flex shrink-0 items-center gap-1">
          {running ? (
            <ToolButton label="Stop" disabled={!controllable || lab.busy} onClick={lab.stop}>
              <Square size={10} strokeWidth={1.75} />
            </ToolButton>
          ) : (
            <ToolButton
              label="Start"
              disabled={!controllable || lab.busy}
              title="Bind 127.0.0.1:17480 (ephemeral port if busy)"
              onClick={() => lab.start(mode)}
            >
              <Play size={10} strokeWidth={1.75} />
            </ToolButton>
          )}
        </div>
      </div>

      <div className="mb-1.5 grid grid-cols-2 border border-line" role="radiogroup" aria-label="Lab mode">
        {MODES.map((m) => {
          const active = mode === m.id;
          return (
            <button
              key={m.id}
              type="button"
              role="radio"
              aria-checked={active}
              title={m.title}
              disabled={!controllable}
              onClick={() => lab.setMode(m.id)}
              className={`flex h-6 items-center justify-center gap-1.5 border-r border-line text-xs last:border-r-0 disabled:cursor-not-allowed ${
                active ? `bg-active ${TONE_TEXT[m.tone]}` : "text-fg-dim hover:bg-active hover:text-fg"
              }`}
            >
              <StatusSquare className={active ? TONE_BG[m.tone] : "bg-muted"} />
              {m.label}
            </button>
          );
        })}
      </div>

      {/* One line instead of metric cells: the route list below owns the remaining height. */}
      <div
        className="num mb-1.5 flex h-4 items-center gap-3 text-2xs text-fg-faint"
        title={
          overRedeemed && counters !== null
            ? `${counters.granted} redemptions granted; the coupon row records ${counters.redeemed} (lost update)`
            : undefined
        }
      >
        <span>
          coupon{" "}
          <span className={overRedeemed ? "text-fault" : "text-fg"}>
            {counters === null ? "-" : `${counters.granted}/${limit}`}
          </span>
        </span>
        <span>
          row <span className="text-fg-dim">{counters?.redeemed ?? "-"}</span>
        </span>
        <span>
          orders <span className="text-fg-dim">{counters?.orders ?? "-"}</span>
        </span>
        <span className="ml-auto">
          req <span className="text-fg-dim">{counters?.requests ?? "-"}</span>
        </span>
      </div>

      {lab.error !== null && (
        <div className="-mx-2.5 mb-1.5">
          <ErrorLine error={lab.error} />
        </div>
      )}

      <div className="flex items-center gap-1">
        <button
          type="button"
          disabled={!running}
          onClick={onLoadTarget}
          title="Target the lab in the inspector, proxy, burst and fuzzer; list its routes"
          className="flex h-6 min-w-0 flex-1 items-center justify-center gap-1 rounded-xs border border-line-strong bg-active px-1.5 text-xs font-medium text-fg-bright hover:border-fg-faint disabled:cursor-not-allowed disabled:border-line disabled:bg-transparent disabled:text-fg-faint"
        >
          <Crosshair size={11} strokeWidth={1.75} />
          <span className="truncate">Load Lab Target</span>
        </button>
        <button
          type="button"
          disabled={!running || !controllable || routing.busy}
          aria-pressed={routing.active}
          onClick={routing.active ? onRouteDirect : onRouteViaProxy}
          title={
            routing.active
              ? `Burst and fuzzer send to the proxy at ${routing.listener ?? "-"} (${routing.armed ? "armed" : "disarmed"}, ${routing.rules} route rule${routing.rules === 1 ? "" : "s"}); click to send directly to the lab`
              : `Start the proxy with the lab as upstream on port ${DEFAULT_LISTEN_PORT} if needed, and send burst and fuzzer traffic through it`
          }
          className={`flex h-6 min-w-0 flex-1 items-center justify-center gap-1 rounded-xs border px-1.5 text-xs font-medium disabled:cursor-not-allowed disabled:border-line disabled:bg-transparent disabled:text-fg-faint ${
            routing.active
              ? routing.armed
                ? "border-warn/60 bg-warn/10 text-warn hover:border-warn"
                : "border-ok/50 bg-ok/10 text-ok hover:border-ok"
              : "border-line-strong bg-active text-fg-bright hover:border-fg-faint"
          }`}
        >
          <Waypoints size={11} strokeWidth={1.75} className="shrink-0" />
          <span className="num truncate">
            {routing.active ? `Via ${routing.listener?.replace(/^127\.0\.0\.1/, "") ?? "proxy"}` : "Via Proxy"}
          </span>
        </button>
        <ToolButton label="Reset" disabled={!controllable} title="Clear coupon ledger and counters" onClick={lab.reset}>
          <RotateCcw size={10} strokeWidth={1.5} />
        </ToolButton>
      </div>
    </div>
  );
}
