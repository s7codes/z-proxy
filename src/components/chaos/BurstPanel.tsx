import { useMemo, useState, type ReactNode } from "react";
import { Zap } from "lucide-react";
import type { BurstControl } from "../../hooks/useBurst";
import type { GuardState } from "../../hooks/useGuardValidator";
import { formatBytes, formatLatency, formatPercent } from "../../lib/format";
import { httpStatusTone, TONE_BG, TONE_TEXT, type Tone } from "../../lib/tone";
import type { Anomaly, AnomalyKind, BurstMethod, BurstReport, HeaderPair } from "../../lib/types";
import { Section, StatusSquare } from "../shell/PanelHeader";
import { ErrorLine } from "./ErrorLine";
import { Slider } from "./Slider";

const METHODS: readonly BurstMethod[] = ["GET", "POST", "PUT", "PATCH", "DELETE"];
const MAX_WORKERS = 100;
const MAX_LISTED_WORKERS = 16;

const ANOMALY_LABEL: Record<AnomalyKind, string> = {
  raceWindow: "Race window",
  statusDivergence: "Status split",
  bodyDivergence: "Body divergence",
  transportErrors: "Transport",
};

interface BurstPanelProps {
  guard: GuardState;
  burst: BurstControl;
  online: boolean;
}

export function BurstPanel({ guard, burst, online }: BurstPanelProps) {
  const [method, setMethod] = useState<BurstMethod>("POST");
  const [path, setPath] = useState("/");
  const [workers, setWorkers] = useState(20);
  const [timeoutMs, setTimeoutMs] = useState(5_000);
  const [headerText, setHeaderText] = useState("");
  const [body, setBody] = useState("");

  const origin = guard.phase === "accepted" ? originOf(guard.target.normalized) : null;
  const parsed = useMemo(() => parseHeaders(headerText), [headerText]);
  const target = origin === null ? null : `${origin}${path.startsWith("/") ? path : `/${path}`}`;
  const canFire = online && target !== null && parsed.error === null && !burst.running;

  const fire = () => {
    if (target === null || parsed.error !== null) return;
    burst.fire({
      target,
      method,
      workers,
      headers: parsed.headers,
      body: body === "" ? null : body,
      timeoutMs,
    });
  };

  return (
    <>
      <div className="flex h-6 shrink-0 items-center gap-2 border-b border-line px-2.5 text-2xs">
        <span className="label-caps text-fg-faint">Origin</span>
        <span className="num truncate text-fg">{origin ?? "no validated target"}</span>
      </div>
      {burst.error !== null && <ErrorLine error={burst.error} />}

      <div className="min-h-0 flex-1 overflow-y-auto">
        <Section title="Request">
          <div className="mb-2 grid grid-cols-5 border border-line">
            {METHODS.map((m) => (
              <button
                key={m}
                type="button"
                onClick={() => setMethod(m)}
                aria-pressed={method === m}
                className={`num h-6 border-r border-line text-2xs last:border-r-0 ${
                  method === m ? "bg-active text-fg-bright" : "text-fg-dim hover:bg-active hover:text-fg"
                }`}
              >
                {m}
              </button>
            ))}
          </div>
          <Field label="Path">
            <input
              value={path}
              onChange={(e) => setPath(e.target.value)}
              spellCheck={false}
              className="num h-5 w-full min-w-0 rounded-xs border border-line bg-bg px-1.5 text-xs text-fg-bright outline-none focus:border-fg-faint"
            />
          </Field>
          <Field label="Headers" error={parsed.error}>
            <textarea
              value={headerText}
              onChange={(e) => setHeaderText(e.target.value)}
              placeholder="Idempotency-Key: order-42"
              spellCheck={false}
              rows={2}
              className="num w-full min-w-0 resize-y rounded-xs border border-line bg-bg px-1.5 py-1 text-xs text-fg-bright outline-none placeholder:text-fg-faint focus:border-fg-faint"
            />
          </Field>
          <Field label="Body">
            <textarea
              value={body}
              onChange={(e) => setBody(e.target.value)}
              placeholder='{"amount":100}'
              spellCheck={false}
              rows={3}
              className="num w-full min-w-0 resize-y rounded-xs border border-line bg-bg px-1.5 py-1 text-xs text-fg-bright outline-none placeholder:text-fg-faint focus:border-fg-faint"
            />
          </Field>
        </Section>

        <Section title="Dispatch">
          <div className="flex flex-col gap-1.5">
            <Slider label="Workers" unit="req" min={1} max={MAX_WORKERS} step={1} value={workers} onChange={setWorkers} />
            <Slider label="Timeout" unit="ms" min={100} max={60000} step={100} value={timeoutMs} onChange={setTimeoutMs} />
          </div>
        </Section>

        {burst.report !== null && <ReportView report={burst.report} />}
      </div>

      <div className="flex h-9 shrink-0 items-center gap-2 border-t border-line px-2.5">
        <span className="text-2xs text-fg-faint">
          {burst.running ? `Barrier armed: ${workers} workers` : "Pre-connected workers, single barrier release"}
        </span>
        <button
          type="button"
          disabled={!canFire}
          onClick={fire}
          className="ml-auto flex h-6 shrink-0 items-center gap-1.5 rounded-xs border border-line-strong bg-active px-2.5 text-xs font-medium text-fg-bright hover:border-fg-faint disabled:cursor-not-allowed disabled:border-line disabled:bg-transparent disabled:text-fg-faint"
        >
          <Zap size={11} strokeWidth={1.75} />
          {burst.running ? "Running" : `Fire ${workers}`}
        </button>
      </div>
    </>
  );
}

function Field({ label, error = null, children }: { label: string; error?: string | null; children: ReactNode }) {
  return (
    <div className="mb-1.5 grid grid-cols-[52px_1fr] items-start gap-2 last:mb-0">
      <span className="pt-0.5 text-xs text-fg-dim">{label}</span>
      <div className="min-w-0">
        {children}
        {error !== null && <div className="num pt-0.5 text-2xs text-fault">{error}</div>}
      </div>
    </div>
  );
}

function ReportView({ report }: { report: BurstReport }) {
  const total = report.samples.length;
  const errors = report.samples.filter((s) => s.status === null).length;

  return (
    <>
      <Section title="Result" aside={<span className="num text-2xs text-fg-faint">{report.id.slice(0, 8)}</span>}>
        <div className="num mb-2 grid grid-cols-4 gap-px border border-line bg-line text-xs">
          <Metric label="spread" value={report.dispatchSpreadUs === null ? "-" : formatLatency(report.dispatchSpreadUs)} />
          <Metric label="wall" value={formatLatency(report.wallUs)} />
          <Metric label="bodies" value={String(report.distinctBodies)} />
          <Metric label="errors" value={String(errors)} tone={errors > 0 ? "fault" : undefined} />
        </div>

        <div className="mb-1.5 flex h-1.5 w-full gap-px" aria-hidden>
          {report.statusHistogram.map((bucket) => (
            <div key={bucket.status ?? "err"} className={TONE_BG[httpStatusTone(bucket.status)]} style={{ flexGrow: bucket.count }} />
          ))}
        </div>
        <div className="num flex flex-col text-xs">
          {report.statusHistogram.map((bucket) => (
            <div key={bucket.status ?? "err"} className="grid h-5 grid-cols-[56px_1fr_56px] items-center">
              <span className={TONE_TEXT[httpStatusTone(bucket.status)]}>{bucket.status ?? "ERR"}</span>
              <span className="text-fg">{bucket.count}</span>
              <span className="text-right text-fg-faint">{formatPercent(bucket.count, total)}</span>
            </div>
          ))}
        </div>
      </Section>

      {report.latency !== null && (
        <Section title="Latency">
          <div className="num grid grid-cols-3 gap-px border border-line bg-line text-xs">
            <Metric label="min" value={formatLatency(report.latency.minUs)} />
            <Metric label="p50" value={formatLatency(report.latency.p50Us)} />
            <Metric label="mean" value={formatLatency(report.latency.meanUs)} />
            <Metric label="p95" value={formatLatency(report.latency.p95Us)} />
            <Metric label="p99" value={formatLatency(report.latency.p99Us)} />
            <Metric label="max" value={formatLatency(report.latency.maxUs)} />
          </div>
          {report.size !== null && (
            <div className="num pt-1.5 text-2xs text-fg-faint">
              size {formatBytes(report.size.minBytes)}
              {report.size.maxBytes !== report.size.minBytes && ` - ${formatBytes(report.size.maxBytes)}`}
            </div>
          )}
        </Section>
      )}

      <Section title="Anomalies" aside={<span className="num text-2xs text-fg-faint">{report.anomalies.length}</span>}>
        {report.anomalies.length === 0 ? (
          <div className="flex items-center gap-1.5 text-xs text-ok">
            <StatusSquare className="bg-ok" />
            Uniform responses across {total} workers
          </div>
        ) : (
          <div className="flex flex-col gap-2">
            {report.anomalies.map((anomaly, i) => (
              <AnomalyRow key={`${anomaly.kind}-${i}`} anomaly={anomaly} />
            ))}
          </div>
        )}
      </Section>
    </>
  );
}

function AnomalyRow({ anomaly }: { anomaly: Anomaly }) {
  const tone: Tone = anomaly.severity === "fault" ? "fault" : "warn";
  const listed = anomaly.workers.slice(0, MAX_LISTED_WORKERS);
  const overflow = anomaly.workers.length - listed.length;
  return (
    <div className={`border-l pl-2 ${tone === "fault" ? "border-fault" : "border-warn"}`}>
      <div className={`label-caps ${TONE_TEXT[tone]}`}>{ANOMALY_LABEL[anomaly.kind]}</div>
      <div className="text-xs text-fg">{anomaly.detail}</div>
      {listed.length > 0 && (
        <div className="num pt-0.5 text-2xs text-fg-faint">
          {listed.map((w) => `w${w}`).join(" ")}
          {overflow > 0 && ` +${overflow}`}
        </div>
      )}
    </div>
  );
}

function Metric({ label, value, tone }: { label: string; value: string; tone?: Tone | undefined }) {
  return (
    <div className="flex flex-col bg-bg px-1.5 py-1">
      <span className="label-caps text-fg-faint">{label}</span>
      <span className={tone === undefined ? "text-fg-bright" : TONE_TEXT[tone]}>{value}</span>
    </div>
  );
}

function originOf(normalized: string): string | null {
  try {
    return new URL(normalized).origin;
  } catch {
    return null;
  }
}

function parseHeaders(text: string): { headers: HeaderPair[]; error: string | null } {
  const headers: HeaderPair[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]?.trim() ?? "";
    if (line === "") continue;
    const colon = line.indexOf(":");
    if (colon <= 0) return { headers, error: `line ${i + 1}: expected "Name: value"` };
    headers.push({ name: line.slice(0, colon).trim(), value: line.slice(colon + 1).trim() });
  }
  return { headers, error: null };
}
