import type { ReactNode } from "react";
import { TONE_TEXT, type Tone } from "../../lib/tone";
import type { BurstMethod } from "../../lib/types";

const METHODS: readonly BurstMethod[] = ["GET", "POST", "PUT", "PATCH", "DELETE"];

export function OriginRow({ origin }: { origin: string | null }) {
  return (
    <div className="flex h-6 shrink-0 items-center gap-2 border-b border-line px-2.5 text-2xs">
      <span className="label-caps text-fg-faint">Origin</span>
      <span className="num truncate text-fg" title={origin ?? undefined}>
        {origin ?? "no validated target"}
      </span>
    </div>
  );
}

export function MethodPicker({ value, onChange }: { value: BurstMethod; onChange: (method: BurstMethod) => void }) {
  return (
    <div className="mb-2 grid grid-cols-5 border border-line">
      {METHODS.map((m) => (
        <button
          key={m}
          type="button"
          onClick={() => onChange(m)}
          aria-pressed={value === m}
          className={`num h-6 border-r border-line text-2xs last:border-r-0 ${
            value === m ? "bg-active text-fg-bright" : "text-fg-dim hover:bg-active hover:text-fg"
          }`}
        >
          {m}
        </button>
      ))}
    </div>
  );
}

export function PathField({
  value,
  onChange,
  unresolved,
}: {
  value: string;
  onChange: (path: string) => void;
  unresolved: readonly string[];
}) {
  return (
    <Field
      label="Path"
      errorTone="warn"
      error={unresolved.length === 0 ? null : `unresolved ${unresolved.map((name) => `{${name}}`).join(" ")}`}
    >
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        spellCheck={false}
        aria-label="Request path"
        className={`num h-5 w-full min-w-0 rounded-xs border bg-bg px-1.5 text-xs text-fg-bright outline-none focus:border-fg-faint ${
          unresolved.length === 0 ? "border-line" : "border-warn/50"
        }`}
      />
    </Field>
  );
}

export function Field({
  label,
  error = null,
  errorTone = "fault",
  children,
}: {
  label: string;
  error?: string | null;
  errorTone?: Tone;
  children: ReactNode;
}) {
  return (
    <div className="mb-1.5 grid grid-cols-[52px_1fr] items-start gap-2 last:mb-0">
      <span className="pt-0.5 text-xs text-fg-dim">{label}</span>
      <div className="min-w-0">
        {children}
        {error !== null && <div className={`num pt-0.5 text-2xs ${TONE_TEXT[errorTone]}`}>{error}</div>}
      </div>
    </div>
  );
}

/** Footer under a payload field when the selected route carries an OpenAPI body sample. */
export function SampleHint({ active, onLoad }: { active: boolean; onLoad: () => void }) {
  return (
    <div className="flex items-center gap-2 pt-0.5 text-2xs text-fg-faint">
      <span>{active ? "OpenAPI request body sample" : "Route has an OpenAPI body sample"}</span>
      {!active && (
        <button type="button" onClick={onLoad} className="ml-auto text-fg-dim hover:text-fg">
          Load sample
        </button>
      )}
    </div>
  );
}

export function Metric({ label, value, tone }: { label: string; value: string; tone?: Tone | undefined }) {
  return (
    <div className="flex flex-col bg-bg px-1.5 py-1">
      <span className="label-caps text-fg-faint">{label}</span>
      <span className={tone === undefined ? "text-fg-bright" : TONE_TEXT[tone]}>{value}</span>
    </div>
  );
}
