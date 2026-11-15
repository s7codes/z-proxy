import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { PanelImperativeHandle } from "react-resizable-panels";
import {
  CircleStop,
  ClipboardCopy,
  Crosshair,
  FlaskConical,
  FileDown,
  FolderOpen,
  PanelBottom,
  PanelLeft,
  PanelRight,
  Pause,
  Play,
  Power,
  RefreshCw,
  RotateCcw,
  ShieldCheck,
  Square,
  Trash2,
  Waypoints,
} from "lucide-react";
import { ChaosControls, DEFAULT_FAULT_PROFILE, type ChaosTab } from "./components/chaos/ChaosControls";
import type { LabRouting } from "./components/inspector/LabPanel";
import { TargetInspector } from "./components/inspector/TargetInspector";
import { CommandPalette, type PaletteCommand } from "./components/shell/CommandPalette";
import { Kbd } from "./components/shell/PanelHeader";
import { StatusBar } from "./components/shell/StatusBar";
import { Workspace } from "./components/shell/Workspace";
import { TelemetryTable } from "./components/telemetry/TelemetryTable";
import { TopologyCanvas } from "./components/topology/TopologyCanvas";
import { useAuditExport } from "./hooks/useAuditExport";
import { useBurst } from "./hooks/useBurst";
import { useEngineStatus } from "./hooks/useEngineStatus";
import { useFuzzer } from "./hooks/useFuzzer";
import { useGuardValidator } from "./hooks/useGuardValidator";
import { useLab } from "./hooks/useLab";
import { sameProfile, useProxy } from "./hooks/useProxy";
import { useRouteScan } from "./hooks/useRouteScan";
import { useTelemetry } from "./hooks/useTelemetry";
import { originOf, type RequestOrigin } from "./lib/request";
import { toBurstMethod, type RequestTarget } from "./lib/routes";
import { DEFAULT_LISTEN_PORT } from "./lib/rules";
import { TONE_TEXT } from "./lib/tone";
import type { DiscoveredRoute, FaultProfile } from "./lib/types";

// Slider drags emit a value per pixel; one IPC round trip per settled position is enough.
const PROFILE_PUSH_MS = 150;
const LAB_RACE_PATH = "/api/v1/coupons/redeem";

export function App() {
  const [targetInput, setTargetInput] = useState("http://127.0.0.1:3000");
  const [faultProfile, setFaultProfile] = useState<FaultProfile>(DEFAULT_FAULT_PROFILE);
  const [paletteOpen, setPaletteOpen] = useState(false);

  const telemetry = useTelemetry();
  const link = useEngineStatus(telemetry.latestHeartbeat, telemetry.latestProxyState);
  const guard = useGuardValidator(targetInput);
  const proxy = useProxy(telemetry.latestProxyState);
  const burst = useBurst();
  const fuzzer = useFuzzer();
  const routeScan = useRouteScan();
  const lab = useLab(telemetry.latestLabState, telemetry.latestLabExchange);
  const [chaosTab, setChaosTab] = useState<ChaosTab>("faults");
  const [selectedRoute, setSelectedRoute] = useState<DiscoveredRoute | null>(null);
  const [requestTarget, setRequestTarget] = useState<RequestTarget>({ method: "POST", path: "/" });
  // Payloads live here rather than in the panels so a route selection (OpenAPI sample) and
  // later a fuzz finding can write them while the owning tab is not mounted.
  const [burstBody, setBurstBody] = useState("");
  const [burstOrigin, setBurstOrigin] = useState<string | null>(null);
  const [fuzzPayload, setFuzzPayload] = useState("");

  const { status: proxyStatus, applyFaults, stop: stopProxy } = proxy;

  const selectRoute = useCallback((route: DiscoveredRoute) => {
    setSelectedRoute(route);
    setRequestTarget((current) => ({ method: toBurstMethod(route.method) ?? current.method, path: route.path }));
    if (route.sampleBody !== null) {
      setBurstBody(route.sampleBody);
      setBurstOrigin(null);
      setFuzzPayload(route.sampleBody);
    }
  }, []);

  const editBurstBody = useCallback((body: string) => {
    setBurstBody(body);
    setBurstOrigin(null);
  }, []);

  // Adopt the engine profile once so a webview reload does not replace an armed profile
  // with the frontend defaults.
  const adoptedProfile = useRef(false);
  useEffect(() => {
    if (adoptedProfile.current || proxyStatus === null) return;
    adoptedProfile.current = true;
    setFaultProfile(proxyStatus.profile);
  }, [proxyStatus]);

  useEffect(() => {
    if (proxyStatus === null || !proxyStatus.armed || sameProfile(proxyStatus.profile, faultProfile)) return;
    const timer = window.setTimeout(() => applyFaults(true, faultProfile), PROFILE_PUSH_MS);
    return () => window.clearTimeout(timer);
  }, [faultProfile, proxyStatus, applyFaults]);

  const targetRef = useRef<HTMLInputElement>(null);
  const inspectorRef = useRef<PanelImperativeHandle | null>(null);
  const chaosRef = useRef<PanelImperativeHandle | null>(null);
  const telemetryRef = useRef<PanelImperativeHandle | null>(null);

  // Fuzz-to-burst escalation: the payload that broke one request is fired from N
  // pre-connected workers, which separates a deterministic crash from one that only
  // surfaces under contention.
  const replayInBurst = useCallback((target: RequestTarget, body: string, origin: string) => {
    setRequestTarget(target);
    setBurstBody(body);
    setBurstOrigin(origin);
    chaosRef.current?.expand();
    setChaosTab("burst");
  }, []);

  // The lab becomes the validated target, so the proxy upstream and the Burst/Fuzzer origin
  // follow from the guard; its routes replace the list and the race-prone redeem route is
  // preselected with its OpenAPI sample body.
  const { adopt: adoptRoutes } = routeScan;
  const { loadRoutes: loadLabRoutes } = lab;
  const labBaseUrl = lab.status?.baseUrl ?? null;
  const loadLabTarget = useCallback(() => {
    if (labBaseUrl === null) return;
    void loadLabRoutes().then((report) => {
      if (report === null) return;
      setTargetInput(labBaseUrl);
      adoptRoutes(report);
      const redeem = report.routes.find((route) => route.method === "POST" && route.path === LAB_RACE_PATH);
      const first = redeem ?? report.routes[0];
      if (first !== undefined) selectRoute(first);
      inspectorRef.current?.expand();
      chaosRef.current?.expand();
      setChaosTab("burst");
    });
  }, [labBaseUrl, loadLabRoutes, adoptRoutes, selectRoute]);

  // Burst and Fuzzer send to the proxy listener while it fronts the validated target, so a
  // route rule bound in the Faults tab shapes the same traffic the lab reports. The inspector
  // keeps the lab as the validated target, which keeps the proxy upstream and the topology
  // pointing at the service rather than at the listener.
  const [viaProxy, setViaProxy] = useState(false);
  const { routeTo: routeProxyTo } = proxy;
  const routeViaProxy = useCallback(() => {
    if (labBaseUrl === null) return;
    void routeProxyTo(labBaseUrl, DEFAULT_LISTEN_PORT).then((status) => {
      if (status === null) return;
      setViaProxy(true);
      if (targetInput === labBaseUrl) {
        chaosRef.current?.expand();
      } else {
        loadLabTarget();
      }
    });
  }, [labBaseUrl, routeProxyTo, targetInput, loadLabTarget]);
  const routeDirect = useCallback(() => setViaProxy(false), []);

  const proxyListener = proxyStatus?.running === true ? proxyStatus.listener : null;
  const validated = guard.phase === "accepted" ? guard.target.normalized.replace(/\/+$/, "") : null;
  const fronted = proxyListener !== null && validated !== null && proxyStatus?.upstream === validated;
  const requestOrigin = useMemo<RequestOrigin | null>(() => {
    if (viaProxy && fronted && proxyListener !== null) {
      return { url: `http://${proxyListener}`, via: validated };
    }
    const direct = validated === null ? null : originOf(validated);
    return direct === null ? null : { url: direct, via: null };
  }, [viaProxy, fronted, proxyListener, validated]);
  const labRoutingActive = requestOrigin?.via != null && labBaseUrl !== null && requestOrigin.via === labBaseUrl;
  const labRouting: LabRouting = {
    active: labRoutingActive,
    listener: proxyListener,
    armed: proxyStatus?.armed ?? false,
    rules: proxyStatus?.rules.length ?? 0,
    busy: proxy.busy,
  };

  const audit = useAuditExport({
    engine: link.state === "online" ? link.status : null,
    targetInput,
    guard,
    requestOrigin,
    lab: lab.status,
    labCounters: lab.counters,
    proxy: proxyStatus,
    burst: burst.report,
    fuzz: fuzzer.report,
  });
  const { save: saveReport, copy: copyReport } = audit;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((open) => !open);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const { setPaused, paused, clear } = telemetry;
  const { scan: scanRoutes, browse: browseRoot, root: scanRoot } = routeScan;
  const { running: fuzzing, cancel: cancelFuzzer } = fuzzer;
  const { status: labStatus, start: startLab, stop: stopLab, setMode: setLabMode, reset: resetLab } = lab;
  const commands = useMemo<PaletteCommand[]>(() => {
    const labCommands: PaletteCommand[] =
      labStatus === null
        ? []
        : labStatus.running
          ? [
              { id: "load-lab", group: "Target Lab", label: "Load lab target", icon: Crosshair, run: loadLabTarget },
              labRoutingActive
                ? {
                    id: "route-direct",
                    group: "Target Lab",
                    label: "Send burst and fuzzer traffic directly to the lab",
                    icon: Waypoints,
                    run: routeDirect,
                  }
                : {
                    id: "route-proxy",
                    group: "Target Lab",
                    label: "Route lab traffic via proxy",
                    icon: Waypoints,
                    run: routeViaProxy,
                  },
              {
                id: "lab-mode",
                group: "Target Lab",
                label: labStatus.mode === "hardened" ? "Switch lab to unprotected" : "Switch lab to hardened",
                icon: ShieldCheck,
                run: () => setLabMode(labStatus.mode === "hardened" ? "unprotected" : "hardened"),
              },
              { id: "reset-lab", group: "Target Lab", label: "Reset lab state", icon: RotateCcw, run: resetLab },
              { id: "stop-lab", group: "Target Lab", label: "Stop target lab", icon: Square, run: stopLab },
            ]
          : [
              {
                id: "start-lab",
                group: "Target Lab",
                label: "Start target lab",
                icon: Play,
                run: () => {
                  inspectorRef.current?.expand();
                  startLab(labStatus.mode);
                },
              },
            ];
    const toggle = (ref: React.RefObject<PanelImperativeHandle | null>) => () => {
      const panel = ref.current;
      if (panel === null) return;
      if (panel.isCollapsed()) panel.expand();
      else panel.collapse();
    };
    return [
      {
        id: "focus-target",
        group: "Target",
        label: "Focus target input",
        icon: Crosshair,
        run: () => {
          inspectorRef.current?.expand();
          requestAnimationFrame(() => targetRef.current?.select());
        },
      },
      {
        id: "browse-root",
        group: "Routes",
        label: "Browse project root",
        icon: FolderOpen,
        run: () => {
          inspectorRef.current?.expand();
          browseRoot();
        },
      },
      ...(scanRoot.trim() === ""
        ? []
        : [{ id: "scan-routes", group: "Routes", label: "Rescan project routes", icon: RefreshCw, run: () => scanRoutes() }]),
      ...labCommands,
      {
        id: "open-fuzzer",
        group: "Fuzzer",
        label: "Open fuzzer panel",
        icon: FlaskConical,
        run: () => {
          chaosRef.current?.expand();
          setChaosTab("fuzzer");
        },
      },
      ...(fuzzing
        ? [{ id: "cancel-fuzzer", group: "Fuzzer", label: "Cancel fuzzer suite", icon: CircleStop, run: cancelFuzzer }]
        : []),
      { id: "pause", group: "Telemetry", label: paused ? "Resume stream" : "Pause stream", icon: Pause, run: () => setPaused(!paused) },
      { id: "clear", group: "Telemetry", label: "Clear buffer", icon: Trash2, run: clear },
      { id: "reset-fault", group: "Fault Injection", label: "Reset fault profile", icon: RotateCcw, run: () => setFaultProfile(DEFAULT_FAULT_PROFILE) },
      ...(proxyStatus === null
        ? []
        : [
            {
              id: "toggle-arm",
              group: "Fault Injection",
              label: proxyStatus.armed ? "Disarm faults" : "Arm faults",
              icon: Power,
              run: () => applyFaults(!proxyStatus.armed, faultProfile),
            },
          ]),
      ...(proxyStatus?.running === true
        ? [{ id: "stop-proxy", group: "Fault Injection", label: "Stop proxy listener", icon: Square, run: stopProxy }]
        : []),
      { id: "export-md", group: "Report", label: "Export audit report (.md)", icon: FileDown, run: () => saveReport("markdown") },
      { id: "export-json", group: "Report", label: "Export audit report (.json)", icon: FileDown, run: () => saveReport("json") },
      { id: "copy-report", group: "Report", label: "Copy audit report as Markdown", icon: ClipboardCopy, run: copyReport },
      { id: "toggle-inspector", group: "Layout", label: "Toggle inspector panel", icon: PanelLeft, run: toggle(inspectorRef) },
      { id: "toggle-chaos", group: "Layout", label: "Toggle chaos panel", icon: PanelRight, run: toggle(chaosRef) },
      { id: "toggle-telemetry", group: "Layout", label: "Toggle telemetry panel", icon: PanelBottom, run: toggle(telemetryRef) },
    ];
  }, [
    saveReport,
    copyReport,
    paused,
    setPaused,
    clear,
    proxyStatus,
    applyFaults,
    stopProxy,
    faultProfile,
    scanRoot,
    scanRoutes,
    browseRoot,
    fuzzing,
    cancelFuzzer,
    labStatus,
    startLab,
    stopLab,
    setLabMode,
    resetLab,
    loadLabTarget,
    labRoutingActive,
    routeDirect,
    routeViaProxy,
  ]);

  // The endpoint node reflects the last fuzz report only while it still describes the
  // request path the panels target. A templated target is compared by its template, since
  // the report's concrete target carries the substituted default identifier.
  const endpointFuzz = useMemo(() => {
    const report = fuzzer.report;
    if (report === null) return null;
    try {
      const reported = report.pathTemplate?.split("?")[0] ?? new URL(report.target).pathname;
      return reported === requestTarget.path.split("?")[0] ? report : null;
    } catch {
      return null;
    }
  }, [fuzzer.report, requestTarget.path]);

  return (
    <div className="flex h-full flex-col bg-bg text-fg">
      <header className="flex h-8 shrink-0 items-center gap-3 border-b border-line bg-panel px-2.5">
        <span className="text-sm font-semibold tracking-tight text-fg-bright">z-proxy</span>
        <span className="h-3.5 w-px bg-line" />
        <span className="text-xs text-fg-dim">workspace</span>
        <span className="num text-xs text-fg">local</span>
        {audit.notice !== null && (
          <span
            className={`num ml-auto min-w-0 truncate text-2xs ${TONE_TEXT[audit.notice.tone]}`}
            title={audit.notice.text}
            role="status"
          >
            {audit.notice.text}
          </span>
        )}
        <div
          className={`flex h-5 shrink-0 items-center rounded-xs border border-line ${audit.notice === null ? "ml-auto" : ""}`}
          role="group"
          aria-label="Export audit report"
        >
          <span className="label-caps flex h-full items-center border-r border-line px-1.5 text-fg-faint">Report</span>
          <ReportButton label=".md" title="Export audit report as Markdown" disabled={audit.busy} onClick={() => saveReport("markdown")}>
            <FileDown size={11} strokeWidth={1.5} />
          </ReportButton>
          <ReportButton label=".json" title="Export audit report as JSON" disabled={audit.busy} onClick={() => saveReport("json")}>
            <FileDown size={11} strokeWidth={1.5} />
          </ReportButton>
          <ReportButton label="Copy" title="Copy the Markdown report to the clipboard" onClick={copyReport}>
            <ClipboardCopy size={11} strokeWidth={1.5} />
          </ReportButton>
        </div>
        <button
          type="button"
          onClick={() => setPaletteOpen(true)}
          className="flex h-5 w-64 shrink-0 items-center gap-2 rounded-xs border border-line bg-bg px-2 text-xs text-fg-faint hover:border-line-strong"
        >
          <span>Search commands</span>
          <span className="ml-auto flex gap-0.5">
            <Kbd>Ctrl</Kbd>
            <Kbd>K</Kbd>
          </span>
        </button>
      </header>

      <Workspace
        panelRefs={{ inspector: inspectorRef, chaos: chaosRef, telemetry: telemetryRef }}
        inspector={
          <TargetInspector
            input={targetInput}
            onInput={setTargetInput}
            guard={guard}
            link={link}
            inputRef={targetRef}
            scan={routeScan}
            selectedRoute={selectedRoute}
            onSelectRoute={selectRoute}
            lab={lab}
            onLoadLab={loadLabTarget}
            labRouting={labRouting}
            onRouteViaProxy={routeViaProxy}
            onRouteDirect={routeDirect}
          />
        }
        topology={
          <TopologyCanvas link={link} guard={guard} proxy={proxyStatus} route={selectedRoute} fuzz={endpointFuzz} />
        }
        chaos={
          <ChaosControls
            tab={chaosTab}
            onTab={setChaosTab}
            profile={faultProfile}
            onChange={setFaultProfile}
            link={link}
            guard={guard}
            requestOrigin={requestOrigin}
            proxy={proxy}
            burst={burst}
            fuzzer={fuzzer}
            fuzzerProgress={telemetry.fuzzerProgress}
            target={requestTarget}
            onTarget={setRequestTarget}
            burstBody={burstBody}
            onBurstBody={editBurstBody}
            fuzzPayload={fuzzPayload}
            onFuzzPayload={setFuzzPayload}
            sampleBody={selectedRoute?.sampleBody ?? null}
            route={selectedRoute}
            burstOrigin={burstOrigin}
            onReplayInBurst={replayInBurst}
          />
        }
        telemetry={<TelemetryTable store={telemetry} />}
      />

      <StatusBar link={link} />
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} commands={commands} />
    </div>
  );
}

function ReportButton({
  label,
  title,
  disabled = false,
  onClick,
  children,
}: {
  label: string;
  title: string;
  disabled?: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      title={title}
      disabled={disabled}
      onClick={onClick}
      className="num flex h-full items-center gap-1 border-r border-line px-1.5 text-2xs text-fg-dim last:border-r-0 hover:bg-active hover:text-fg disabled:cursor-not-allowed disabled:text-fg-faint"
    >
      {children}
      {label}
    </button>
  );
}
