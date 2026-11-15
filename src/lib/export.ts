import type { GuardState } from "../hooks/useGuardValidator";
import type { AuditRecord, TrafficAudit } from "../hooks/useTelemetry";
import { describeViolation } from "./contract";
import { formatBytes, formatLatency, formatPercent } from "./format";
import { RISK_KINDS, RISK_LABEL } from "./risk";
import type { RequestOrigin } from "./request";
import { ruleLabel, summarizeProfile } from "./rules";
import { AUDIT_KINDS, AUDIT_LABEL, type AuditKind } from "./traffic";
import type {
  Anomaly,
  BurstReport,
  ContractViolation,
  ClassSummary,
  EngineStatus,
  FaultProfile,
  FuzzCaseResult,
  FuzzReport,
  FuzzVerdict,
  HostKind,
  LabCounters,
  LabMode,
  LabStatus,
  LatencyStats,
  MutationClass,
  ProbeResult,
  ProxyStatus,
  ReportFormat,
  RouteMethod,
  RouteRiskKind,
  RouteScanReport,
} from "./types";

/** Version 2 added the passive traffic audit, contract drift, static route risks and the
 * idempotency replay summary. */
export const AUDIT_SCHEMA = "z-proxy.audit/2";
/** Findings listed in Markdown; the JSON rendering carries all of them. */
const MARKDOWN_FINDINGS = 200;

/** Session state an audit report is built from; everything the UI already holds. */
export interface AuditInputs {
  generatedAt: Date;
  engine: EngineStatus | null;
  targetInput: string;
  guard: GuardState;
  requestOrigin: RequestOrigin | null;
  lab: LabStatus | null;
  labCounters: LabCounters | null;
  proxy: ProxyStatus | null;
  burst: BurstReport | null;
  fuzz: FuzzReport | null;
  /** Passive findings and contract drift folded from proxied exchanges. */
  traffic: TrafficAudit;
  /** Route list in view: a project scan or the lab document. */
  routes: RouteScanReport | null;
}

export interface AuditRule {
  index: number;
  method: RouteMethod | null;
  pathPattern: string;
  profile: FaultProfile;
  summary: string;
}

export interface AuditFuzz {
  id: string;
  target: string;
  method: FuzzReport["method"];
  pathTemplate: string | null;
  fields: number;
  wallUs: number;
  baseline: { status: number | null; verdict: FuzzVerdict; latencyUs: number };
  cases: number;
  executed: number;
  faults: number;
  warnings: number;
  disclosures: number;
  aborted: string | null;
  notes: string[];
  classes: MutationClass[];
  summary: ClassSummary[];
  /** Cases with a severity, faults first. */
  findings: FuzzCaseResult[];
}

export interface AuditTraffic {
  exchanges: number;
  counts: Record<AuditKind, number>;
  faults: number;
  /** Passive findings, faults first; contract drift is listed under `contracts`. */
  findings: AuditRecord[];
  /** Counters exceed the retained records; the oldest were dropped. */
  truncated: boolean;
}

export interface AuditFuzzDrift {
  index: number;
  label: string;
  status: number | null;
  violations: ContractViolation[];
}

export interface AuditContracts {
  /** Contracts the proxy checked forwarded responses against. */
  proxyContracts: number;
  proxied: AuditRecord[];
  /** Requests of the last fuzz suite, baseline included, whose response drifted. */
  fuzzRequests: number;
  fuzzCases: AuditFuzzDrift[];
}

export interface AuditRouteRisk {
  kind: RouteRiskKind;
  method: RouteMethod;
  path: string;
  file: string;
  line: number;
  evidence: string;
  detail: string;
}

export interface AuditRoutes {
  root: string;
  routes: number;
  atRisk: number;
  counts: Record<RouteRiskKind, number>;
  risks: AuditRouteRisk[];
}

export interface AuditIdempotency {
  key: string;
  target: string;
  workers: number;
  successes: number;
  distinctBodies: number;
  /** `null` when every 2xx response replayed one body. */
  violation: Anomaly | null;
}

/** Versioned, self-describing snapshot; the JSON export is this object verbatim. */
export interface AuditReport {
  schema: typeof AUDIT_SCHEMA;
  generatedAt: string;
  engine: {
    version: string | null;
    uptimeMs: number | null;
    guardMode: string | null;
    allowlist: string[];
  };
  target: {
    input: string;
    verdict: GuardState["phase"];
    normalized: string | null;
    hostKind: HostKind | null;
    probe: ProbeResult | null;
    rejection: { code: string; message: string } | null;
    requestOrigin: RequestOrigin | null;
  };
  lab: {
    running: boolean;
    listener: string | null;
    mode: LabMode;
    couponCode: string;
    couponLimit: number;
    counters: LabCounters;
  } | null;
  proxy: {
    running: boolean;
    listener: string | null;
    upstream: string | null;
    armed: boolean;
    profile: FaultProfile;
    profileSummary: string;
    rules: AuditRule[];
  } | null;
  burst: BurstReport | null;
  idempotency: AuditIdempotency | null;
  fuzz: AuditFuzz | null;
  traffic: AuditTraffic;
  contracts: AuditContracts;
  routes: AuditRoutes | null;
}

function severityRank(result: FuzzCaseResult): number {
  return result.severity === "fault" ? 0 : 1;
}

function buildTraffic(traffic: TrafficAudit): AuditTraffic {
  const findings = traffic.records
    .filter((record) => record.kind !== "contractDrift")
    .sort((a, b) => (a.severity === b.severity ? a.seq - b.seq : a.severity === "fault" ? -1 : 1));
  const counted = AUDIT_KINDS.reduce((sum, kind) => sum + traffic.counts[kind], 0);
  return {
    exchanges: traffic.exchanges,
    counts: { ...traffic.counts },
    faults: traffic.faults,
    findings,
    truncated: counted > traffic.records.length,
  };
}

function buildContracts(inputs: AuditInputs): AuditContracts {
  const { fuzz } = inputs;
  const fuzzCases =
    fuzz === null
      ? []
      : [fuzz.baseline, ...fuzz.cases]
          .filter((result) => result.violations.length > 0)
          .map((result) => ({
            index: result.index,
            label: result.label,
            status: result.status,
            violations: result.violations,
          }));
  return {
    proxyContracts: inputs.proxy?.contracts ?? 0,
    proxied: inputs.traffic.records.filter((record) => record.kind === "contractDrift"),
    fuzzRequests: fuzz?.contractViolations ?? 0,
    fuzzCases,
  };
}

function buildRoutes(report: RouteScanReport | null): AuditRoutes | null {
  if (report === null) return null;
  const counts: Record<RouteRiskKind, number> = { unvalidatedMutation: 0, unboundedQuery: 0, floatingAsync: 0 };
  const risks: AuditRouteRisk[] = [];
  for (const route of report.routes) {
    for (const risk of route.risks) {
      counts[risk.kind] += 1;
      risks.push({
        kind: risk.kind,
        method: route.method,
        path: route.path,
        file: route.file,
        line: risk.line,
        evidence: risk.evidence,
        detail: risk.detail,
      });
    }
  }
  return {
    root: report.root,
    routes: report.routes.length,
    atRisk: report.routes.filter((route) => route.risks.length > 0).length,
    counts,
    risks,
  };
}

function buildIdempotency(burst: BurstReport | null): AuditIdempotency | null {
  if (burst === null || burst.idempotencyKey === null) return null;
  const successes = burst.samples.filter((s) => s.status !== null && s.status >= 200 && s.status < 300);
  return {
    key: burst.idempotencyKey,
    target: burst.target,
    workers: burst.workers,
    successes: successes.length,
    distinctBodies: new Set(successes.map((s) => s.bodyHash)).size,
    violation: burst.anomalies.find((anomaly) => anomaly.kind === "idempotencyViolation") ?? null,
  };
}

export function buildAuditReport(inputs: AuditInputs): AuditReport {
  const { guard, engine, lab, proxy, fuzz } = inputs;
  return {
    schema: AUDIT_SCHEMA,
    generatedAt: inputs.generatedAt.toISOString(),
    engine: {
      version: engine?.version ?? null,
      uptimeMs: engine?.uptimeMs ?? null,
      guardMode: engine?.guardMode ?? null,
      allowlist: engine === null ? [] : [...engine.allowlist],
    },
    target: {
      input: inputs.targetInput,
      verdict: guard.phase,
      normalized: guard.phase === "accepted" ? guard.target.normalized : null,
      hostKind: guard.phase === "accepted" ? guard.target.hostKind : null,
      probe: guard.phase === "accepted" ? guard.target.probe : null,
      rejection: guard.phase === "rejected" ? { code: guard.error.code, message: guard.error.message } : null,
      requestOrigin: inputs.requestOrigin,
    },
    lab:
      lab === null
        ? null
        : {
            running: lab.running,
            listener: lab.listener,
            mode: lab.mode,
            couponCode: lab.couponCode,
            couponLimit: lab.couponLimit,
            counters: inputs.labCounters ?? lab.counters,
          },
    proxy:
      proxy === null
        ? null
        : {
            running: proxy.running,
            listener: proxy.listener,
            upstream: proxy.upstream,
            armed: proxy.armed,
            profile: proxy.profile,
            profileSummary: summarizeProfile(proxy.profile),
            rules: proxy.rules.map((rule, index) => ({
              index: index + 1,
              method: rule.method,
              pathPattern: rule.pathPattern,
              profile: rule.profile,
              summary: summarizeProfile(rule.profile),
            })),
          },
    burst: inputs.burst,
    idempotency: buildIdempotency(inputs.burst),
    traffic: buildTraffic(inputs.traffic),
    contracts: buildContracts(inputs),
    routes: buildRoutes(inputs.routes),
    fuzz:
      fuzz === null
        ? null
        : {
            id: fuzz.id,
            target: fuzz.target,
            method: fuzz.method,
            pathTemplate: fuzz.pathTemplate,
            fields: fuzz.fields,
            wallUs: fuzz.wallUs,
            baseline: {
              status: fuzz.baseline.status,
              verdict: fuzz.baseline.verdict,
              latencyUs: fuzz.baseline.latencyUs,
            },
            cases: fuzz.cases.length,
            executed: fuzz.cases.filter((c) => c.verdict !== "skipped").length,
            faults: fuzz.faults,
            warnings: fuzz.warnings,
            disclosures: fuzz.disclosures,
            aborted: fuzz.aborted,
            notes: fuzz.notes,
            classes: fuzz.classes,
            summary: fuzz.summary,
            findings: fuzz.cases
              .filter((c) => c.severity !== null)
              .sort((a, b) => severityRank(a) - severityRank(b) || a.index - b.index),
          },
  };
}

export function renderAuditReport(report: AuditReport, format: ReportFormat): string {
  return format === "json" ? `${JSON.stringify(report, null, 2)}\n` : renderMarkdown(report);
}

/** `z-proxy-audit-20261115-183000.md`, local time. */
export function auditFileName(generatedAt: Date, format: ReportFormat): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  const date = `${generatedAt.getFullYear()}${pad(generatedAt.getMonth() + 1)}${pad(generatedAt.getDate())}`;
  const time = `${pad(generatedAt.getHours())}${pad(generatedAt.getMinutes())}${pad(generatedAt.getSeconds())}`;
  return `z-proxy-audit-${date}-${time}.${format === "json" ? "json" : "md"}`;
}

// ---- markdown -------------------------------------------------------------------------

/** Table cell text: pipes escaped, line breaks flattened. */
function cell(value: string | number | null | undefined): string {
  if (value === null || value === undefined || value === "") return "-";
  return String(value).replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

/** Inline code span, fenced longer than any backtick run inside (CommonMark). */
function code(value: string | null | undefined): string {
  if (value === null || value === undefined || value === "") return "-";
  const longest = Math.max(0, ...Array.from(value.matchAll(/`+/g), (m) => m[0].length));
  const fence = "`".repeat(longest + 1);
  const padded = value.startsWith("`") || value.endsWith("`") ? ` ${value} ` : value;
  return `${fence}${padded.replace(/\r?\n/g, " ").replace(/\|/g, "\\|")}${fence}`;
}

function table(headers: readonly string[], rows: ReadonlyArray<readonly string[]>): string {
  const head = `| ${headers.join(" | ")} |`;
  const rule = `|${headers.map(() => "---").join("|")}|`;
  return [head, rule, ...rows.map((row) => `| ${row.join(" | ")} |`)].join("\n");
}

function fields(rows: ReadonlyArray<readonly [string, string]>): string {
  return table(["Field", "Value"], rows.map(([key, value]) => [key, value]));
}

function yesNo(flag: boolean): string {
  return flag ? "yes" : "no";
}

function count(n: number, singular: string, plural = `${singular}s`): string {
  return `${n} ${n === 1 ? singular : plural}`;
}

function latencyRows(ttfb: LatencyStats | null, total: LatencyStats): string[][] {
  const keys: ReadonlyArray<readonly [string, keyof LatencyStats]> = [
    ["min", "minUs"],
    ["p50", "p50Us"],
    ["p95", "p95Us"],
    ["p99", "p99Us"],
    ["max", "maxUs"],
    ["mean", "meanUs"],
  ];
  return keys.map(([label, key]) => [
    label,
    ttfb === null ? "-" : formatLatency(ttfb[key]),
    formatLatency(total[key]),
    ttfb === null ? "-" : formatLatency(Math.max(0, total[key] - ttfb[key])),
  ]);
}

function probeText(probe: ProbeResult | null): string {
  if (probe === null) return "-";
  return probe.state === "reachable"
    ? `HEAD ${probe.status} in ${formatLatency(probe.latencyUs)}`
    : `unreachable after ${formatLatency(probe.latencyUs)}: ${probe.reason}`;
}

function overview(report: AuditReport): string[][] {
  const rows: string[][] = [];
  const { burst, fuzz } = report;
  if (burst === null) {
    rows.push(["Concurrency burst", "not run"]);
  } else {
    const faults = burst.anomalies.filter((a) => a.severity === "fault").length;
    const kinds = burst.anomalies.map((a) => `${a.kind} (${a.severity})`).join(", ");
    rows.push([
      "Concurrency burst",
      burst.anomalies.length === 0
        ? `uniform across ${count(burst.workers, "worker")}`
        : cell(`${count(burst.anomalies.length, "anomaly", "anomalies")} (${count(faults, "fault")}): ${kinds}`),
    ]);
  }
  if (fuzz === null) {
    rows.push(["Payload fuzzer", "not run"]);
  } else {
    rows.push([
      "Payload fuzzer",
      cell(
        `${count(fuzz.faults, "fault")}, ${count(fuzz.warnings, "warning")}, ${count(fuzz.disclosures, "disclosure")} across ${count(fuzz.executed, "case")}${
          fuzz.aborted === null ? "" : `; aborted: ${fuzz.aborted}`
        }`,
      ),
    ]);
  }
  const { idempotency } = report;
  if (idempotency !== null) {
    rows.push([
      "Idempotency replay",
      idempotency.violation === null
        ? cell(`held: ${count(idempotency.successes, "2xx response")} replayed one body`)
        : cell(`violated (fault): ${idempotency.violation.detail}`),
    ]);
  }
  const { traffic, contracts, routes } = report;
  rows.push([
    "Passive traffic audit",
    traffic.exchanges === 0
      ? "no proxied traffic"
      : cell(
          `${count(traffic.findings.length, "finding")} (${count(traffic.faults, "fault")}) across ${count(traffic.exchanges, "exchange")}${
            traffic.findings.length === 0
              ? ""
              : `: ${AUDIT_KINDS.filter((k) => k !== "contractDrift" && traffic.counts[k] > 0)
                  .map((k) => `${traffic.counts[k]} ${AUDIT_LABEL[k].toLowerCase()}`)
                  .join(", ")}`
          }`,
        ),
  ]);
  rows.push([
    "Contract drift",
    contracts.proxyContracts === 0 && contracts.fuzzCases.length === 0
      ? "no response contracts in use"
      : cell(
          `${count(contracts.proxied.length, "proxied violation")}, ${count(contracts.fuzzRequests, "fuzz request")} with drift`,
        ),
  ]);
  rows.push([
    "Static route audit",
    routes === null
      ? "no route scan"
      : cell(`${routes.atRisk} of ${count(routes.routes, "route")} at risk, ${count(routes.risks.length, "finding")}`),
  ]);
  const proxy = report.proxy;
  rows.push([
    "Fault injection",
    proxy === null
      ? "engine unavailable"
      : proxy.armed
        ? cell(`armed, global ${proxy.profileSummary}, ${count(proxy.rules.length, "route rule")}`)
        : "disarmed",
  ]);
  return rows;
}

function renderMarkdown(report: AuditReport): string {
  const out: string[] = [];
  // Every block (heading, paragraph, table) is followed by a blank line, so a table never
  // runs into the heading or paragraph next to it.
  const push = (...blocks: string[]) => {
    for (const block of blocks) out.push(block, "");
  };

  push(
    "# z-proxy audit report",
    fields([
      ["Generated", code(report.generatedAt)],
      ["Schema", code(report.schema)],
      ["Engine", report.engine.version === null ? "unavailable" : cell(`z-proxy ${report.engine.version}`)],
      [
        "Loopback guard",
        report.engine.allowlist.length === 0
          ? "-"
          : cell(`${report.engine.guardMode ?? "strict"}: ${report.engine.allowlist.join(", ")}`),
      ],
    ]),
  );

  push("## Overview", table(["Area", "Result"], overview(report)));

  const { target } = report;
  const origin = target.requestOrigin;
  push(
    "## Target",
    fields([
      ["Input", code(target.input)],
      [
        "Guard verdict",
        target.verdict === "rejected" && target.rejection !== null
          ? cell(`rejected: ${target.rejection.code} ${target.rejection.message}`)
          : target.verdict,
      ],
      ["Normalized", code(target.normalized)],
      ["Host kind", cell(target.hostKind)],
      ["Probe", cell(probeText(target.probe))],
      [
        "Request origin",
        origin === null ? "-" : origin.via === null ? code(origin.url) : `${code(origin.url)} via proxy to ${code(origin.via)}`,
      ],
    ]),
  );

  const { lab } = report;
  if (lab !== null) {
    const over = lab.counters.granted > lab.couponLimit;
    push(
      "## Target lab",
      fields([
        ["Running", lab.running ? `yes, ${code(lab.listener)}` : "no"],
        ["Mode", lab.mode],
        [
          "Coupon",
          cell(
            `${lab.couponCode}: ${lab.counters.granted} granted, limit ${lab.couponLimit}, row ${lab.counters.redeemed}${
              over ? " (over-redeemed)" : ""
            }`,
          ),
        ],
        ["Orders confirmed", String(lab.counters.orders)],
        ["Requests served", String(lab.counters.requests)],
      ]),
    );
  }

  const { proxy } = report;
  if (proxy !== null) {
    push(
      "## Reverse proxy",
      fields([
        ["Listener", proxy.running ? code(proxy.listener) : "offline"],
        ["Upstream", code(proxy.upstream)],
        ["Armed", yesNo(proxy.armed)],
        ["Global profile", cell(proxy.profileSummary)],
      ]),
    );
    if (proxy.rules.length > 0) {
      push(
        "### Route rules",
        "First match wins; matched against the upstream path while armed.",
        table(
          ["#", "Rule", "Profile"],
          proxy.rules.map((rule) => [
            String(rule.index),
            code(ruleLabel({ method: rule.method, pathPattern: rule.pathPattern, profile: rule.profile })),
            cell(rule.summary),
          ]),
        ),
      );
    }
  }

  const { burst } = report;
  push("## Concurrency burst");
  if (burst === null) {
    push("No burst run in this session.");
  } else {
    const total = burst.statusHistogram.reduce((sum, bucket) => sum + bucket.count, 0);
    const errors = burst.statusHistogram.find((bucket) => bucket.status === null)?.count ?? 0;
    push(
      fields([
        ["Run", code(burst.id)],
        ["Request", `${burst.method} ${code(burst.target)}`],
        ["Workers", String(burst.workers)],
        ["Success quota", burst.expectedMaxSuccesses === null ? "none" : `at most ${burst.expectedMaxSuccesses} 2xx`],
        ["Idempotency-Key", burst.idempotencyKey === null ? "not replayed" : `${code(burst.idempotencyKey)} from every worker`],
        ["Wall time", formatLatency(burst.wallUs)],
        ["Dispatch spread", burst.dispatchSpreadUs === null ? "-" : formatLatency(burst.dispatchSpreadUs)],
        ["Distinct bodies", String(burst.distinctBodies)],
        [
          "Response size",
          burst.size === null
            ? "-"
            : burst.size.minBytes === burst.size.maxBytes
              ? formatBytes(burst.size.minBytes)
              : `${formatBytes(burst.size.minBytes)} - ${formatBytes(burst.size.maxBytes)}`,
        ],
        ["Transport errors", String(errors)],
      ]),
      "### Status histogram",
      table(
        ["Status", "Count", "Share"],
        burst.statusHistogram.map((bucket) => [
          bucket.status === null ? "no response" : String(bucket.status),
          String(bucket.count),
          formatPercent(bucket.count, total),
        ]),
      ),
    );
    if (burst.latency !== null) {
      push(
        "### Latency",
        "Nearest-rank percentiles over responded workers. TTFB runs from the request write to the parsed response head; total to the last body frame.",
        table(["Percentile", "TTFB", "Total", "Body"], latencyRows(burst.ttfb, burst.latency)),
      );
    }
    push(
      "### Anomalies",
      burst.anomalies.length === 0
        ? `None: uniform responses across ${total} workers.`
        : table(
            ["Kind", "Severity", "Workers", "Detail"],
            burst.anomalies.map((a) => [
              code(a.kind),
              a.severity,
              cell(a.workers.length === 0 ? "-" : a.workers.map((w) => `w${w}`).join(" ")),
              cell(a.detail),
            ]),
          ),
    );
  }

  const { fuzz } = report;
  push("## Payload fuzzer");
  if (fuzz === null) {
    push("No fuzzer suite run in this session.");
  } else {
    push(
      fields([
        ["Run", code(fuzz.id)],
        ["Request", `${fuzz.method} ${code(fuzz.target)}`],
        ["Path template", code(fuzz.pathTemplate)],
        ["Fields mutated", String(fuzz.fields)],
        [
          "Baseline",
          fuzz.baseline.status === null
            ? fuzz.baseline.verdict
            : `${fuzz.baseline.status} in ${formatLatency(fuzz.baseline.latencyUs)}`,
        ],
        ["Cases executed", fuzz.executed === fuzz.cases ? String(fuzz.cases) : `${fuzz.executed} of ${fuzz.cases}`],
        ["Faults", String(fuzz.faults)],
        ["Warnings", String(fuzz.warnings)],
        ["Disclosures", String(fuzz.disclosures)],
        ["Wall time", formatLatency(fuzz.wallUs)],
        ["Aborted", cell(fuzz.aborted)],
      ]),
      "### Vectors",
      table(
        ["Class", "Cases", "4xx", "2xx", "Faults", "Unreached"],
        fuzz.summary.map((row) => [
          code(row.class),
          String(row.cases),
          String(row.rejected),
          String(row.accepted),
          String(row.faults),
          String(row.unreached),
        ]),
      ),
    );
    if (fuzz.notes.length > 0) {
      push("### Notes", fuzz.notes.map((note) => `- ${note.replace(/\r?\n/g, " ")}`).join("\n"));
    }
    const listed = fuzz.findings.slice(0, MARKDOWN_FINDINGS);
    push(
      "### Findings",
      fuzz.findings.length === 0
        ? `None: no 5xx, transport failures, leaked traces or contract drift across ${fuzz.executed} cases.`
        : table(
            ["#", "Class", "Case", "Status", "Severity", "Latency", "Disclosure"],
            listed.map((f) => [
              String(f.index),
              f.class === null ? "baseline" : code(f.class),
              code(f.label.length > 160 ? `${f.label.slice(0, 160)}...` : f.label),
              f.status === null ? cell(f.verdict) : String(f.status),
              f.severity ?? "-",
              f.latencyUs === 0 ? "-" : formatLatency(f.latencyUs),
              f.disclosure !== null
                ? cell(`${f.disclosure.kind}: ${f.disclosure.evidence}`)
                : f.violations[0] !== undefined
                  ? cell(`drift ${describeViolation(f.violations[0])}`)
                  : cell(f.error),
            ]),
          ),
    );
    if (fuzz.findings.length > listed.length) {
      push(`${fuzz.findings.length - listed.length} further findings are listed in the JSON export.`);
    }
  }

  renderTraffic(report.traffic, push);
  renderContracts(report.contracts, push);
  renderRoutes(report.routes, push);

  return `${out.join("\n").trimEnd()}\n`;
}

type Push = (...blocks: string[]) => void;

function requestCell(record: AuditRecord): string {
  return code(`${record.method} ${record.path}`);
}

function renderTraffic(traffic: AuditTraffic, push: Push): void {
  push("## Passive traffic audit");
  if (traffic.exchanges === 0) {
    push("No traffic passed through the proxy in this session.");
    return;
  }
  push(
    fields([
      ["Exchanges audited", String(traffic.exchanges)],
      ...AUDIT_KINDS.filter((kind) => kind !== "contractDrift").map(
        (kind) => [AUDIT_LABEL[kind], String(traffic.counts[kind])] as [string, string],
      ),
    ]),
  );
  const listed = traffic.findings.slice(0, MARKDOWN_FINDINGS);
  push(
    "### Findings",
    listed.length === 0
      ? `None across ${count(traffic.exchanges, "exchange")}.`
      : table(
          ["Seq", "Request", "Status", "Kind", "Severity", "Detail", "Evidence"],
          listed.map((f) => [
            String(f.seq),
            requestCell(f),
            f.status === null ? "RST" : String(f.status),
            code(f.kind),
            f.severity,
            cell(f.detail),
            code(f.evidence),
          ]),
        ),
  );
  if (traffic.findings.length > listed.length || traffic.truncated) {
    push("Further findings are counted above; the JSON export lists every retained record.");
  }
}

function renderContracts(contracts: AuditContracts, push: Push): void {
  push("## Contract drift");
  if (contracts.proxyContracts === 0 && contracts.fuzzCases.length === 0 && contracts.proxied.length === 0) {
    push("No OpenAPI response contracts were in use: scan an OpenAPI document or load the lab target.");
    return;
  }
  push(
    fields([
      ["Proxy contracts", String(contracts.proxyContracts)],
      ["Proxied violations", String(contracts.proxied.length)],
      ["Fuzz requests with drift", String(contracts.fuzzRequests)],
    ]),
  );
  if (contracts.proxied.length > 0) {
    push(
      "### Proxied responses",
      table(
        ["Seq", "Request", "Status", "Contract", "Violation"],
        contracts.proxied.slice(0, MARKDOWN_FINDINGS).map((record) => [
          String(record.seq),
          requestCell(record),
          record.status === null ? "RST" : String(record.status),
          code(record.contract),
          cell(record.violation === null ? record.detail : describeViolation(record.violation)),
        ]),
      ),
    );
  }
  if (contracts.fuzzCases.length > 0) {
    push(
      "### Fuzzer cases",
      table(
        ["#", "Case", "Status", "Violations"],
        contracts.fuzzCases.slice(0, MARKDOWN_FINDINGS).map((drift) => [
          String(drift.index),
          code(drift.label.length > 120 ? `${drift.label.slice(0, 120)}...` : drift.label),
          drift.status === null ? "-" : String(drift.status),
          cell(drift.violations.map(describeViolation).join("; ")),
        ]),
      ),
    );
  }
}

function renderRoutes(routes: AuditRoutes | null, push: Push): void {
  push("## Static route audit");
  if (routes === null) {
    push("No route scan in this session.");
    return;
  }
  push(
    fields([
      ["Root", code(routes.root)],
      ["Routes", String(routes.routes)],
      ["At risk", String(routes.atRisk)],
      ...RISK_KINDS.map((kind) => [RISK_LABEL[kind], String(routes.counts[kind])] as [string, string]),
    ]),
  );
  if (routes.risks.length === 0) {
    push("No unvalidated mutations, unbounded queries or floating async calls found.");
    return;
  }
  push(
    table(
      ["Kind", "Route", "Location", "Evidence", "Detail"],
      routes.risks.slice(0, MARKDOWN_FINDINGS).map((risk) => [
        code(risk.kind),
        code(`${risk.method} ${risk.path}`),
        code(`${risk.file}:${risk.line}`),
        code(risk.evidence),
        cell(risk.detail),
      ]),
    ),
  );
  if (routes.risks.length > MARKDOWN_FINDINGS) {
    push(`${routes.risks.length - MARKDOWN_FINDINGS} further risks are listed in the JSON export.`);
  }
}
