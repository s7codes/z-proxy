import { useMemo, useState } from "react";
import { Zap } from "lucide-react";
import type { BurstControl } from "../../hooks/useBurst";
import { formatBytes, formatLatency, formatPercent } from "../../lib/format";
import { joinTarget, parseHeaders, type RequestOrigin } from "../../lib/request";
import { pathParams, type RequestTarget } from "../../lib/routes";
import { httpStatusTone, TONE_BG, TONE_TEXT, type Tone } from "../../lib/tone";
import type { Anomaly, AnomalyKind, BurstReport, LatencyStats } from "../../lib/types";
import { Section, StatusSquare } from "../shell/PanelHeader";
import { ErrorLine } from "./ErrorLine";
import { Field, MethodPicker, Metric, OriginRow, PathField, SampleHint } from "./RequestFields";
import { Slider } from "./Slider";

const MAX_WORKERS = 100;
const MAX_LISTED_WORKERS = 16;

const ANOMALY_LABEL: Record<AnomalyKind, string> = {
  raceWindow: "Race window",
  statusDivergence: "Status split",
  bodyDivergence: "Body divergence",
  transportErrors: "Transport",
};

interface BurstPanelProps {
  /** Validated target, or the proxy listener in front of it. */
  requestOrigin: RequestOrigin | null;
  burst: BurstControl;
  online: boolean;
  target: RequestTarget;
  onTarget: (target: RequestTarget) => void;
  body: string;
  onBody: (body: string) => void;
  sampleBody: string | null;
  /** Set while the body is a replayed fuzz case; editing the body clears it. */
  origin: string | null;
}

export function BurstPanel({
  requestOrigin,
  burst,
  online,
  target: request,
  onTarget,
  body,
  onBody: setBody,
  sampleBody,
  origin: bodyOrigin,
}: BurstPanelProps) {
  const { method, path } = request;
  const [workers, setWorkers] = useState(20);
  const [timeoutMs, setTimeoutMs] = useState(5_000);
  // 0 means no quota; the engine receives `null`.
  const [maxSuccesses, setMaxSuccesses] = useState(0);
  const [headerText, setHeaderText] = useState("");

  const parsed = useMemo(() => parseHeaders(headerText), [headerText]);
  const params = pathParams(path);
  const target = requestOrigin === null ? null : joinTarget(requestOrigin.url, path);
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
      expectedMaxSuccesses: maxSuccesses === 0 ? null : maxSuccesses,
    });
  };

  return (
    <>
      <OriginRow origin={requestOrigin} />
      {burst.error !== null && <ErrorLine error={burst.error} />}

      <div className="min-h-0 flex-1 overflow-y-auto">
        <Section title="Request">
          <MethodPicker value={method} onChange={(m) => onTarget({ method: m, path })} />
          <PathField value={path} onChange={(p) => onTarget({ method, path: p })} params={params} />
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
            {bodyOrigin !== null && (
              <div className="num truncate pt-0.5 text-2xs text-warn" title={bodyOrigin}>
                {bodyOrigin}
              </div>
            )}
            {sampleBody !== null && (
              <SampleHint active={body === sampleBody} onLoad={() => setBody(sampleBody)} />
            )}
          </Field>
        </Section>

        <Section title="Dispatch">
          <div className="flex flex-col gap-1.5">
            <Slider label="Workers" unit="req" min={1} max={MAX_WORKERS} step={1} value={workers} onChange={setWorkers} />
            <Slider label="Timeout" unit="ms" min={100} max={60000} step={100} value={timeoutMs} onChange={setTimeoutMs} />
            <QuotaField value={maxSuccesses} max={workers} onChange={setMaxSuccesses} />
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
        <Section title="Latency" aside={<span className="num text-2xs text-fg-faint">nearest rank</span>}>
          <LatencyGrid ttfb={report.ttfb} total={report.latency} />
          {report.size !== null && (
            <div className="num pt-1.5 text-2xs text-fg-faint">
              size {formatBytes(report.size.minBytes)}
              {report.size.maxBytes !== report.size.minBytes && ` - ${formatBytes(report.size.maxBytes)}`}
            </div>
          )}
        </Section>
      )}

      <Section
        title="Anomalies"
        aside={
          <span className="num text-2xs text-fg-faint">
            {report.expectedMaxSuccesses === null ? "" : `max 2xx ${report.expectedMaxSuccesses}  `}
            {report.anomalies.length}
          </span>
        }
      >
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

const LATENCY_ROWS: ReadonlyArray<{ label: string; key: keyof LatencyStats }> = [
  { label: "min", key: "minUs" },
  { label: "p50", key: "p50Us" },
  { label: "p95", key: "p95Us" },
  { label: "p99", key: "p99Us" },
  { label: "max", key: "maxUs" },
  { label: "mean", key: "meanUs" },
];

/** TTFB next to total exchange time; the gap is time spent producing or streaming the body. */
function LatencyGrid({ ttfb, total }: { ttfb: LatencyStats | null; total: LatencyStats }) {
  return (
    <div className="num border border-line text-xs">
      <div className="grid h-5 grid-cols-[40px_1fr_1fr_1fr] items-center border-b border-line bg-bg px-1.5 text-2xs text-fg-faint">
        <span />
        <span className="text-right">ttfb</span>
        <span className="text-right">total</span>
        <span className="text-right">body</span>
      </div>
      {LATENCY_ROWS.map(({ label, key }) => {
        const head = ttfb?.[key] ?? null;
        const end = total[key];
        return (
          <div key={key} className="grid h-5 grid-cols-[40px_1fr_1fr_1fr] items-center border-b border-line/60 px-1.5 last:border-b-0">
            <span className="text-2xs text-fg-faint">{label}</span>
            <span className="text-right text-fg-bright">{head === null ? "-" : formatLatency(head)}</span>
            <span className="text-right text-fg-bright">{formatLatency(end)}</span>
            <span className="text-right text-fg-dim">{head === null ? "-" : formatLatency(Math.max(0, end - head))}</span>
          </div>
        );
      })}
    </div>
  );
}

function QuotaField({ value, max, onChange }: { value: number; max: number; onChange: (value: number) => void }) {
  return (
    <div className="flex h-5 items-center gap-2 text-xs">
      <span className="w-[52px] shrink-0 text-fg-dim">Max 2xx</span>
      <input
        type="number"
        min={0}
        max={max}
        value={value}
        aria-label="Expected maximum successes"
        onChange={(e) => {
          const next = Number(e.target.value);
          if (Number.isInteger(next) && next >= 0 && next <= 65_535) onChange(next);
        }}
        className="num h-5 w-12 rounded-xs border border-line bg-bg px-1 text-right text-xs text-fg-bright outline-none focus:border-fg-faint [appearance:textfield] [&::-webkit-inner-spin-button]:appearance-none"
      />
      <span className="min-w-0 truncate text-2xs text-fg-faint">
        {value === 0 ? "no quota; race needs a conflict response" : `more than ${value} success${value === 1 ? "" : "es"} is a race`}
      </span>
    </div>
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

