import { Crosshair, Play, RotateCcw, Square } from "lucide-react";
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

interface LabPanelProps {
  lab: LabControl;
  online: boolean;
  onLoadTarget: () => void;
}

/** Start/stop, defect mode and live counters of the embedded target lab. */
export function LabPanel({ lab, online, onLoadTarget }: LabPanelProps) {
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
          className="flex h-6 min-w-0 flex-1 items-center justify-center gap-1.5 rounded-xs border border-line-strong bg-active px-2 text-xs font-medium text-fg-bright hover:border-fg-faint disabled:cursor-not-allowed disabled:border-line disabled:bg-transparent disabled:text-fg-faint"
        >
          <Crosshair size={11} strokeWidth={1.75} />
          Load Lab Target
        </button>
        <ToolButton label="Reset" disabled={!controllable} title="Clear coupon ledger and counters" onClick={lab.reset}>
          <RotateCcw size={10} strokeWidth={1.5} />
        </ToolButton>
      </div>
    </div>
  );
}
