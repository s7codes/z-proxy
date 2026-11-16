import { useMemo, useState } from "react";
import { FileInput, FlaskConical, Square, X, Zap } from "lucide-react";
import type { FuzzerControl } from "../../hooks/useFuzzer";
import type { FuzzerProgress } from "../../hooks/useTelemetry";
import { contractSummary, describeViolation, VIOLATION_LABEL } from "../../lib/contract";
import { DISCLOSURE_LABEL } from "../../lib/disclosure";
import { formatBytes, formatLatency } from "../../lib/format";
import { materializeFuzzCase } from "../../lib/ipc";
import type { FuzzPreset } from "../../lib/risk";
import { joinTarget, parseHeaders, type RequestOrigin } from "../../lib/request";
import { pathParams, type RequestTarget } from "../../lib/routes";
import { httpStatusTone, TONE_BG, TONE_TEXT, type Tone } from "../../lib/tone";
import type {
  FuzzCaseResult,
  FuzzReport,
  FuzzVerdict,
  HeaderPair,
  MutationClass,
  ResponseContract,
} from "../../lib/types";
import { Section, StatusDot } from "../shell/PanelHeader";
import { ErrorLine } from "./ErrorLine";
import { Field, MethodPicker, Metric, OriginRow, PathField } from "./RequestFields";
import { Slider } from "./Slider";

const CLASSES: ReadonlyArray<{ id: MutationClass; label: string; short: string }> = [
  { id: "nullInjection", label: "Null injection", short: "null" },
  { id: "emptyStrings", label: "Empty strings", short: "empty" },
  { id: "boundaryNumbers", label: "Boundary numbers", short: "boundary" },
  { id: "typeConfusion", label: "Type confusion", short: "type" },
  { id: "oversizedField", label: "Oversized 64 KiB", short: "oversize" },
  { id: "malformedJson", label: "Malformed JSON", short: "malformed" },
  { id: "missingFields", label: "Missing fields", short: "missing" },
  { id: "schemaContractBounds", label: "Schema contract", short: "contract" },
  { id: "pathParamValidation", label: "Path parameters", short: "path" },
  { id: "delimiterEscaping", label: "Delimiter escaping", short: "delimiter" },
  { id: "queryAndHeaderBounds", label: "Query & headers", short: "query" },
];

/** Classes whose case bodies cannot seed a base payload, which must be a plain JSON object. */
const UNSEEDABLE: ReadonlySet<MutationClass> = new Set<MutationClass>([
  // Not an object at all.
  "malformedJson",
  // A duplicate key or a 1e309 literal would be lost or refused when the engine re-parses it.
  "schemaContractBounds",
  // The body is the unmodified base.
  "pathParamValidation",
  "queryAndHeaderBounds",
]);

const SHORT: Record<MutationClass, string> = Object.fromEntries(CLASSES.map((c) => [c.id, c.short])) as Record<
  MutationClass,
  string
>;

// Mirrors the engine's built-in template (fuzzer.rs default_template) so "Template" shows
// exactly what an empty payload field sends.
const TEMPLATE = `{
  "id": 1,
  "name": "z-proxy",
  "email": "fuzz@zproxy.invalid",
  "quantity": 1,
  "active": true,
  "tags": ["alpha"],
  "meta": { "source": "z-proxy" }
}`;

const MAX_LISTED_FINDINGS = 200;
const MAX_LISTED_VIOLATIONS = 3;

const VERDICT_LABEL: Record<FuzzVerdict, string> = {
  rejected: "4xx",
  accepted: "2xx",
  serverError: "5xx",
  transportFailure: "ABORT",
  unreachable: "DOWN",
  skipped: "SKIP",
};

interface FuzzerPanelProps {
  /** Validated target, or the proxy listener in front of it. */
  requestOrigin: RequestOrigin | null;
  fuzzer: FuzzerControl;
  progress: FuzzerProgress | null;
  online: boolean;
  target: RequestTarget;
  onTarget: (target: RequestTarget) => void;
  payload: string;
  onPayload: (payload: string) => void;
  sampleBody: string | null;
  /** OpenAPI response contract of the targeted operation; responses are checked against it. */
  contract: ResponseContract | null;
  /** Replays a case through the burst runner: same method, path, body and header overrides, N workers. */
  onSendToBurst: (target: RequestTarget, body: string, origin: string, headers: HeaderPair[]) => void;
  /** Initial mutation classes from an auto-targeted route risk. */
  preset: FuzzPreset | null;
}

export function FuzzerPanel({
  requestOrigin,
  fuzzer,
  progress,
  online,
  target: request,
  onTarget,
  payload,
  onPayload: setPayload,
  sampleBody,
  contract,
  onSendToBurst,
  preset,
}: FuzzerPanelProps) {
  const { method, path } = request;
  const [headerText, setHeaderText] = useState("");
  const [selected, setSelected] = useState<ReadonlySet<MutationClass>>(
    () => new Set(preset?.classes ?? CLASSES.map((c) => c.id)),
  );
  const [timeoutMs, setTimeoutMs] = useState(5_000);

  const parsed = useMemo(() => parseHeaders(headerText), [headerText]);
  const payloadError = useMemo(() => validatePayload(payload), [payload]);
  const params = pathParams(path);
  const target = requestOrigin === null ? null : joinTarget(requestOrigin.url, path);
  const canRun =
    online &&
    target !== null &&
    parsed.error === null &&
    payloadError === null &&
    selected.size > 0 &&
    !fuzzer.running;

  const toggle = (id: MutationClass) =>
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const run = () => {
    if (!canRun || target === null) return;
    fuzzer.run({
      target,
      method,
      headers: parsed.headers,
      baseBody: payload.trim() === "" ? null : payload,
      classes: CLASSES.filter((c) => selected.has(c.id)).map((c) => c.id),
      timeoutMs,
      contract,
    });
  };

  const live = fuzzer.running && progress !== null && !progress.finished ? progress : null;

  return (
    <>
      <OriginRow origin={requestOrigin} />
      {fuzzer.error !== null && <ErrorLine error={fuzzer.error} />}

      <div className="min-h-0 flex-1 overflow-y-auto">
        <Section title="Request">
          <MethodPicker value={method} onChange={(m) => onTarget({ method: m, path })} />
          <PathField value={path} onChange={(p) => onTarget({ method, path: p })} params={params} varied />
          <Field label="Headers" error={parsed.error}>
            <textarea
              value={headerText}
              onChange={(e) => setHeaderText(e.target.value)}
              placeholder="Authorization: Bearer dev-token"
              spellCheck={false}
              rows={2}
              className="num w-full min-w-0 resize-y field px-1.5 py-1 text-xs placeholder:text-fg-faint"
            />
          </Field>
          <Field label="Payload" error={payloadError}>
            <textarea
              value={payload}
              onChange={(e) => setPayload(e.target.value)}
              placeholder="empty: built-in template"
              spellCheck={false}
              rows={5}
              className="num w-full min-w-0 resize-y field px-1.5 py-1 text-xs placeholder:text-fg-faint"
            />
            <div className="flex items-center gap-2 pt-0.5 text-2xs text-fg-faint">
              <span className="truncate">
                {sampleBody !== null && payload === sampleBody
                  ? "OpenAPI request body sample"
                  : "JSON object; nested objects mutate to depth 3"}
              </span>
              {sampleBody !== null && payload !== sampleBody && (
                <button
                  type="button"
                  onClick={() => setPayload(sampleBody)}
                  className="ml-auto shrink-0 text-fg-dim hover:text-fg"
                >
                  Sample
                </button>
              )}
              <button
                type="button"
                onClick={() => setPayload(TEMPLATE)}
                className={`shrink-0 text-fg-dim hover:text-fg ${sampleBody !== null && payload !== sampleBody ? "" : "ml-auto"}`}
              >
                Template
              </button>
            </div>
          </Field>
          {method === "GET" && (
            <div className="pt-1 text-2xs text-fg-faint">GET bodies are commonly ignored; prefer the route's write method.</div>
          )}
          <div className="num truncate pt-1 text-2xs text-fg-faint" title={contract === null ? undefined : contractSummary(contract)}>
            {contract === null
              ? "No response contract; select an OpenAPI route to check responses for drift"
              : `response contract: ${contractSummary(contract)}`}
          </div>
        </Section>

        <Section
          title="Vectors"
          aside={
            <span className="num text-2xs text-fg-faint">
              {selected.size}/{CLASSES.length}
            </span>
          }
        >
          <div className="grid grid-cols-2 gap-px border border-line bg-line">
            {CLASSES.map((c) => {
              const on = selected.has(c.id);
              const slotless = c.id === "pathParamValidation" && params.length === 0;
              return (
                <button
                  key={c.id}
                  type="button"
                  title={slotless ? `${c.label}: the path has no {param} slot, so this vector adds no cases` : c.label}
                  aria-pressed={on}
                  onClick={() => toggle(c.id)}
                  className={`flex h-6 items-center gap-1.5 px-1.5 text-left text-xs ${
                    on ? "bg-active text-fg-bright" : "bg-bg text-fg-faint hover:text-fg-dim"
                  }`}
                >
                  <span className={`size-1.5 shrink-0 border ${on ? "border-fg-dim bg-fg-dim" : "border-line-strong"}`} />
                  <span className="truncate">{c.label}</span>
                  {c.id === "pathParamValidation" && (
                    <span className="num ml-auto shrink-0 text-2xs text-fg-faint">
                      {slotless ? "no slots" : `${params.length}x7`}
                    </span>
                  )}
                </button>
              );
            })}
            {CLASSES.length % 2 === 1 && <span className="bg-bg" aria-hidden />}
          </div>
        </Section>

        <Section title="Dispatch">
          <Slider label="Timeout" unit="ms" min={100} max={60000} step={100} value={timeoutMs} onChange={setTimeoutMs} />
        </Section>

        {fuzzer.report !== null && (
          <FuzzReportView
            key={fuzzer.report.id}
            report={fuzzer.report}
            onLoadPayload={setPayload}
            onSendToBurst={onSendToBurst}
          />
        )}
      </div>

      <div className="flex shrink-0 flex-col border-t border-line">
        {live !== null && (
          <div className="h-px w-full bg-line" aria-hidden>
            <div
              className={live.faults > 0 ? "h-px bg-fault" : "h-px bg-fg-dim"}
              style={{ width: `${live.total === 0 ? 0 : (live.completed / live.total) * 100}%` }}
            />
          </div>
        )}
        <div className="flex h-9 items-center gap-2 px-2.5">
          <span className="num min-w-0 truncate text-2xs text-fg-faint">
            {live !== null
              ? `${live.completed}/${live.total} cases  ${live.faults} fault${live.faults === 1 ? "" : "s"}`
              : fuzzer.running
                ? "Baseline request in flight"
                : "Baseline, then one connection per case"}
          </span>
          {fuzzer.running ? (
            <button
              type="button"
              disabled={fuzzer.cancelling}
              onClick={fuzzer.cancel}
              className="btn ml-auto shrink-0"
            >
              <Square size={10} strokeWidth={1.75} />
              {fuzzer.cancelling ? "Cancelling" : "Cancel"}
            </button>
          ) : (
            <button
              type="button"
              disabled={!canRun}
              onClick={run}
              className="btn btn-primary ml-auto shrink-0"
            >
              <FlaskConical size={11} strokeWidth={1.75} />
              Run suite
            </button>
          )}
        </div>
      </div>
    </>
  );
}

function validatePayload(text: string): string | null {
  if (text.trim() === "") return null;
  try {
    const value: unknown = JSON.parse(text);
    if (typeof value !== "object" || value === null || Array.isArray(value)) return "must be a JSON object";
    return null;
  } catch (err: unknown) {
    return err instanceof Error ? err.message : "not valid JSON";
  }
}

function caseTone(result: FuzzCaseResult): Tone {
  if (result.severity === "fault") return "fault";
  if (result.severity === "warn") return "warn";
  if (result.verdict === "unreachable" || result.verdict === "skipped") return "muted";
  return result.verdict === "rejected" ? "ok" : "muted";
}

/** Path and query the suite targeted, so a replay hits the same resource. */
function reportPath(report: FuzzReport): string | null {
  try {
    const url = new URL(report.target);
    return `${url.pathname}${url.search}`;
  } catch {
    return null;
  }
}

type ReplayNotice = { tone: Tone; text: string };

function FuzzReportView({
  report,
  onLoadPayload,
  onSendToBurst,
}: {
  report: FuzzReport;
  onLoadPayload: (payload: string) => void;
  onSendToBurst: (target: RequestTarget, body: string, origin: string, headers: HeaderPair[]) => void;
}) {
  const [expanded, setExpanded] = useState<number | null>(null);
  const [pending, setPending] = useState<number | null>(null);
  const [notice, setNotice] = useState<ReplayNotice | null>(null);
  const executed = report.cases.filter((c) => c.verdict !== "skipped").length;

  // Bodies (and paths of path cases) are rebuilt by the engine from the report's base body,
  // classes and path template rather than kept per case: generation is deterministic, and
  // oversize cases are 64 KiB each.
  const replay = (result: FuzzCaseResult, destination: "burst" | "fuzzer") => {
    setPending(result.index);
    void materializeFuzzCase({
      baseBody: report.baseBody,
      classes: report.classes,
      pathTemplate: report.pathTemplate,
      index: result.index,
      target: report.target,
    }).then(
      (outcome) => {
        setPending(null);
        if (!outcome.ok) {
          setNotice({ tone: "fault", text: `${outcome.error.code} ${outcome.error.message}` });
          return;
        }
        const payload = outcome.value;
        if (destination === "fuzzer") {
          if (validatePayload(payload.body) !== null || payload.body.trim() === "") {
            setNotice({ tone: "warn", text: `#${payload.index} is not a JSON object; it can seed a burst, not the fuzzer` });
            return;
          }
          onLoadPayload(payload.body);
          setNotice({ tone: "muted", text: `#${payload.index} ${payload.label} loaded as base payload` });
          return;
        }
        // A path or query case replays its exact target; a body case keeps the template, so
        // the burst runner substitutes the same default identifier the suite used.
        const path = payload.path ?? report.pathTemplate ?? reportPath(report);
        if (path === null) {
          setNotice({ tone: "fault", text: `cannot derive a path from ${report.target}` });
          return;
        }
        const origin = `fuzz case #${payload.index} ${payload.label}${
          payload.lossy ? "; invalid UTF-8 replaced with U+FFFD" : ""
        }`;
        onSendToBurst({ method: report.method, path }, payload.body, origin, payload.headers);
      },
    );
  };
  const findings = report.cases
    .filter((c) => c.severity !== null)
    .sort((a, b) => (a.severity === b.severity ? a.index - b.index : a.severity === "fault" ? -1 : 1));
  const listed = findings.slice(0, MAX_LISTED_FINDINGS);
  const { baseline } = report;

  return (
    <>
      <Section
        title="Result"
        aside={
          <span className="num text-2xs text-fg-faint">
            {`${formatLatency(report.wallUs)}  `}
            {report.id.slice(0, 8)}
          </span>
        }
      >
        <div className="num mb-2 grid grid-cols-3 gap-px border border-line bg-line text-xs">
          <Metric label="cases" value={executed === report.cases.length ? String(executed) : `${executed}/${report.cases.length}`} />
          <Metric label="faults" value={String(report.faults)} tone={report.faults > 0 ? "fault" : undefined} />
          <Metric label="warns" value={String(report.warnings)} tone={report.warnings > 0 ? "warn" : undefined} />
          <Metric label="leaks" value={String(report.disclosures)} tone={report.disclosures > 0 ? "warn" : undefined} />
          <Metric
            label="drift"
            value={String(report.contractViolations)}
            tone={report.contractViolations > 0 ? "warn" : undefined}
          />
          <Metric
            label="echo"
            value={String(report.massAssignments)}
            tone={report.massAssignments > 0 ? "fault" : undefined}
          />
        </div>
        <div className="num grid grid-cols-[64px_1fr_auto] items-center text-xs">
          <span className="text-fg-faint">baseline</span>
          <span className={TONE_TEXT[baseline.status === null ? "fault" : httpStatusTone(baseline.status)]}>
            {baseline.status ?? VERDICT_LABEL[baseline.verdict]}
          </span>
          <span className="text-fg-faint">{baseline.status === null ? "-" : formatLatency(baseline.latencyUs)}</span>
          <span className="text-fg-faint">fields</span>
          <span className="text-fg">{report.fields}</span>
          <span className="text-fg-faint">{formatBytes(baseline.requestBytes)}</span>
        </div>
        {report.aborted !== null && (
          <div className="num flex items-center gap-1.5 pt-1.5 text-2xs text-warn">
            <StatusDot className="bg-warn" />
            {report.aborted}
          </div>
        )}
        {report.notes.map((note) => (
          <div key={note} className="pt-1 text-2xs text-fg-dim">
            {note}
          </div>
        ))}
      </Section>

      <Section title="Vectors">
        <div className="num text-xs">
          <div className="grid h-5 grid-cols-[1fr_32px_32px_32px_36px_32px] items-center text-2xs text-fg-faint">
            <span>class</span>
            <span className="text-right">n</span>
            <span className="text-right">4xx</span>
            <span className="text-right">2xx</span>
            <span className="text-right">fault</span>
            <span className="text-right">skip</span>
          </div>
          {report.summary.map((row) => (
            <div key={row.class} className="grid h-5 grid-cols-[1fr_32px_32px_32px_36px_32px] items-center border-t border-line/60">
              <span className="truncate text-fg-dim">{SHORT[row.class]}</span>
              <span className="text-right text-fg">{row.cases}</span>
              <span className="text-right text-fg">{row.rejected}</span>
              <span className="text-right text-fg">{row.accepted}</span>
              <span className={`text-right ${row.faults > 0 ? "text-fault" : "text-fg-faint"}`}>{row.faults}</span>
              <span className="text-right text-fg-faint">{row.unreached}</span>
            </div>
          ))}
        </div>
      </Section>

      <Section title="Findings" aside={<span className="num text-2xs text-fg-faint">{findings.length}</span>}>
        {notice !== null && (
          <div className={`num mb-1.5 flex items-start gap-1.5 text-2xs ${TONE_TEXT[notice.tone]}`}>
            <span className="min-w-0 flex-1 break-words">{notice.text}</span>
            <button
              type="button"
              aria-label="Dismiss"
              onClick={() => setNotice(null)}
              className="shrink-0 text-fg-faint hover:text-fg"
            >
              <X size={10} strokeWidth={1.5} />
            </button>
          </div>
        )}
        {findings.length === 0 ? (
          <div className="flex items-center gap-1.5 text-xs text-ok">
            <StatusDot className="bg-ok" />
            No 5xx, transport failures, leaks, mass assignments or contract drift across {executed} cases
          </div>
        ) : (
          <div className="flex flex-col gap-1.5">
            {listed.map((result) => (
              <FindingRow
                key={result.index}
                result={result}
                expanded={expanded === result.index}
                onToggle={() => setExpanded((current) => (current === result.index ? null : result.index))}
                pending={pending === result.index}
                onReplay={(destination) => replay(result, destination)}
              />
            ))}
            {findings.length > listed.length && (
              <div className="num text-2xs text-fg-faint">+{findings.length - listed.length} more in telemetry</div>
            )}
          </div>
        )}
      </Section>
    </>
  );
}

function FindingRow({
  result,
  expanded,
  onToggle,
  pending,
  onReplay,
}: {
  result: FuzzCaseResult;
  expanded: boolean;
  onToggle: () => void;
  pending: boolean;
  onReplay: (destination: "burst" | "fuzzer") => void;
}) {
  const tone = caseTone(result);
  const hasDetail = result.responsePreview !== null;
  const seedable = result.class === null || !UNSEEDABLE.has(result.class);
  return (
    <div className={`border-l pl-2 ${tone === "fault" ? "border-fault" : "border-warn"}`}>
      <button
        type="button"
        onClick={onToggle}
        disabled={!hasDetail}
        aria-expanded={hasDetail ? expanded : undefined}
        className="flex w-full flex-col text-left disabled:cursor-default"
      >
        <span className="num flex w-full items-center gap-1.5 text-2xs">
          <span className="text-fg-faint">#{result.index}</span>
          <span className={`caption ${TONE_TEXT[tone]}`}>{result.class === null ? "baseline" : SHORT[result.class]}</span>
          <span className={`ml-auto flex items-center gap-1 ${TONE_TEXT[tone]}`}>
            <StatusDot className={TONE_BG[tone]} />
            {result.status ?? VERDICT_LABEL[result.verdict]}
          </span>
          <span className="w-14 text-right text-fg-faint">{result.latencyUs === 0 ? "-" : formatLatency(result.latencyUs)}</span>
        </span>
        <span className="num truncate text-xs text-fg" title={result.label}>
          {result.label}
        </span>
      </button>
      {result.error !== null && <div className="num text-2xs text-fg-dim">{result.error}</div>}
      {result.massAssignment !== null && (
        <div className="num flex min-w-0 items-center gap-1.5 text-2xs" title={result.massAssignment.detail}>
          <span className="shrink-0 text-fault">Mass assignment</span>
          <span className="truncate text-fg-dim">{`${result.massAssignment.echoedAt} = ${result.massAssignment.value}`}</span>
        </div>
      )}
      {result.disclosure !== null && (
        <div className="num flex min-w-0 items-center gap-1.5 text-2xs" title={result.disclosure.evidence}>
          <span className="shrink-0 text-warn">{DISCLOSURE_LABEL[result.disclosure.kind]}</span>
          <span className="truncate text-fg-dim">{result.disclosure.evidence}</span>
        </div>
      )}
      {result.violations.slice(0, MAX_LISTED_VIOLATIONS).map((violation) => (
        <div
          key={`${violation.kind}${violation.pointer ?? ""}`}
          className="num flex min-w-0 items-center gap-1.5 text-2xs"
          title={describeViolation(violation)}
        >
          <span className="shrink-0 text-warn">{VIOLATION_LABEL[violation.kind]}</span>
          <span className="truncate text-fg-dim">{describeViolation(violation)}</span>
        </div>
      ))}
      {result.violations.length > MAX_LISTED_VIOLATIONS && (
        <div className="num text-2xs text-fg-faint">+{result.violations.length - MAX_LISTED_VIOLATIONS} more drift</div>
      )}
      {expanded && result.responsePreview !== null && (
        <pre className="num mt-1 max-h-40 overflow-auto whitespace-pre-wrap break-all rounded-xs border border-line bg-field p-1.5 text-2xs leading-4 text-fg-dim select-text">
          {result.responsePreview}
        </pre>
      )}
      <div className="flex items-center gap-3 pt-0.5 text-2xs">
        <button
          type="button"
          disabled={pending}
          onClick={() => onReplay("burst")}
          title="Fire this exact body from N concurrent workers"
          className="flex items-center gap-1 text-fg-dim hover:text-fg disabled:text-fg-faint"
        >
          <Zap size={10} strokeWidth={1.5} />
          Send to burst
        </button>
        {seedable && (
          <button
            type="button"
            disabled={pending}
            onClick={() => onReplay("fuzzer")}
            title="Use this body as the fuzzer base payload"
            className="flex items-center gap-1 text-fg-dim hover:text-fg disabled:text-fg-faint"
          >
            <FileInput size={10} strokeWidth={1.5} />
            Load payload
          </button>
        )}
        {pending && <span className="text-fg-faint">rebuilding</span>}
      </div>
    </div>
  );
}
