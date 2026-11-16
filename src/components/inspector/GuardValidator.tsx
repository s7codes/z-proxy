import type { Ref } from "react";
import { Crosshair, LoaderCircle } from "lucide-react";
import type { GuardState } from "../../hooks/useGuardValidator";
import { formatLatency } from "../../lib/format";
import { guardTone, httpStatusTone, TONE_BG, TONE_TEXT, type Tone } from "../../lib/tone";
import { StatusDot } from "../shell/PanelHeader";

interface GuardValidatorProps {
  value: string;
  onChange: (value: string) => void;
  state: GuardState;
  inputRef: Ref<HTMLInputElement>;
}

export function GuardValidator({ value, onChange, state, inputRef }: GuardValidatorProps) {
  const tone = guardTone(state);
  const borderTone =
    state.phase === "rejected" ? "!border-fault" : state.phase === "accepted" ? "!border-ok/70" : "";

  return (
    <div className="flex flex-col gap-2">
      <label className={`field flex h-[26px] items-center gap-1.5 px-2 ${borderTone}`}>
        <Crosshair size={13} strokeWidth={1.5} className="shrink-0 text-fg-faint" />
        <input
          ref={inputRef}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          spellCheck={false}
          autoComplete="off"
          placeholder="http://127.0.0.1:3000"
          aria-label="Target URL"
          className="num min-w-0 flex-1 bg-transparent text-sm text-fg-bright outline-none placeholder:text-fg-faint"
        />
        {state.phase === "pending" && (
          <LoaderCircle size={12} strokeWidth={1.5} className="shrink-0 animate-spin text-fg-faint" />
        )}
      </label>

      <dl className="grid grid-cols-[64px_1fr] gap-x-2 gap-y-0.5 text-xs">
        <Row label="Verdict">
          <span className={`flex items-center gap-1.5 font-medium ${TONE_TEXT[verdictTone(state)]}`}>
            <StatusDot className={TONE_BG[verdictTone(state)]} />
            {verdictLabel(state)}
          </span>
        </Row>
        {state.phase === "rejected" && (
          <>
            <Row label="Code">
              <span className="num text-fault">{state.error.code}</span>
            </Row>
            {"host" in state.error && (
              <Row label="Host">
                <span className="num text-fg">{state.error.host}</span>
              </Row>
            )}
            <Row label="Reason">
              <span className="text-fg-dim">{state.error.message}</span>
            </Row>
          </>
        )}
        {state.phase === "offline" && (
          <Row label="Reason">
            <span className="text-fg-dim">{state.reason}</span>
          </Row>
        )}
        {state.phase === "accepted" && (
          <>
            <Row label="Endpoint">
              <span className="num break-all text-fg">{state.target.normalized}</span>
            </Row>
            <Row label="Host">
              <span className="num text-fg">
                {state.target.host}
                <span className="text-fg-faint"> / {state.target.hostKind}</span>
              </span>
            </Row>
            <Row label="Port">
              <span className="num text-fg">{state.target.port}</span>
            </Row>
            <Row label="Probe">
              {state.target.probe.state === "reachable" ? (
                <span className="num">
                  <span className={TONE_TEXT[httpStatusTone(state.target.probe.status)]}>
                    HEAD {state.target.probe.status}
                  </span>
                  <span className="text-fg-dim"> {formatLatency(state.target.probe.latencyUs)}</span>
                </span>
              ) : (
                <span className="num">
                  <span className="text-warn">{state.target.probe.reason}</span>
                  <span className="text-fg-faint"> {formatLatency(state.target.probe.latencyUs)}</span>
                </span>
              )}
            </Row>
          </>
        )}
      </dl>
      <span className="sr-only" aria-live="polite">
        {tone === "fault" ? "Target rejected" : tone === "ok" ? "Target accepted" : ""}
      </span>
    </div>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <>
      <dt className="text-fg-faint">{label}</dt>
      <dd className="min-w-0">{children}</dd>
    </>
  );
}

function verdictTone(state: GuardState): Tone {
  switch (state.phase) {
    case "accepted":
      return "ok";
    case "rejected":
      return "fault";
    default:
      return "muted";
  }
}

function verdictLabel(state: GuardState): string {
  switch (state.phase) {
    case "empty":
      return "No target";
    case "pending":
      return "Validating";
    case "accepted":
      return "Accepted";
    case "rejected":
      return "Rejected";
    case "offline":
      return "Engine offline";
  }
}
