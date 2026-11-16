import type { ReactNode } from "react";
import type { RequestOrigin } from "../../lib/request";
import { DEFAULT_PATH_VALUE } from "../../lib/routes";
import { TONE_TEXT, type Tone } from "../../lib/tone";
import type { BurstMethod } from "../../lib/types";

const METHODS: readonly BurstMethod[] = ["GET", "POST", "PUT", "PATCH", "DELETE"];

export function OriginRow({ origin }: { origin: RequestOrigin | null }) {
  const title = origin === null ? undefined : origin.via === null ? origin.url : `${origin.url} -> ${origin.via}`;
  return (
    <div className="flex h-6 shrink-0 items-center gap-2 border-b border-line px-2.5 text-2xs">
      <span className="caption text-fg-faint">Origin</span>
      <span className="num min-w-0 truncate text-fg" title={title}>
        {origin?.url ?? "no validated target"}
      </span>
      {origin?.via != null && (
        <span className="num ml-auto flex min-w-0 shrink items-center gap-1 text-warn">
          <span className="shrink-0">via proxy</span>
          <span className="truncate text-fg-faint">{`-> ${origin.via}`}</span>
        </span>
      )}
    </div>
  );
}

export function MethodPicker({ value, onChange }: { value: BurstMethod; onChange: (method: BurstMethod) => void }) {
  return (
    <div className="mb-2 grid grid-cols-5 overflow-hidden rounded-xs border border-line-strong">
      {METHODS.map((m) => (
        <button
          key={m}
          type="button"
          onClick={() => onChange(m)}
          aria-pressed={value === m}
          className={`num h-6 border-r border-line text-2xs last:border-r-0 ${
            value === m ? "bg-select text-select-fg" : "bg-control text-fg hover:bg-active"
          }`}
        >
          {m}
        </button>
      ))}
    </div>
  );
}

/** Path input; `{param}` placeholders are sent as the engine default, which the note states. */
export function PathField({
  value,
  onChange,
  params,
  varied = false,
}: {
  value: string;
  onChange: (path: string) => void;
  params: readonly string[];
  /** The fuzzer's path vectors rewrite each slot; say so next to the default. */
  varied?: boolean;
}) {
  const slots = params.map((name) => `{${name}}`).join(" ");
  const note =
    params.length === 0
      ? null
      : `${slots} sent as ${DEFAULT_PATH_VALUE}${varied ? "; path vectors vary each slot" : ""}`;
  return (
    <Field label="Path" errorTone="muted" error={note}>
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        spellCheck={false}
        aria-label="Request path"
        className="num h-5 w-full min-w-0 field px-1.5 text-xs"
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
      <span className="caption text-fg-faint">{label}</span>
      <span className={tone === undefined ? "text-fg-bright" : TONE_TEXT[tone]}>{value}</span>
    </div>
  );
}
