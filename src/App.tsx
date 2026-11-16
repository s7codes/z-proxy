import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { PanelImperativeHandle } from "react-resizable-panels";
import {
  CircleStop,
  ClipboardCopy,
  Crosshair,
  FlaskConical,
  FileDown,
  FolderOpen,
  ListFilter,
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
import {
  ChaosControls,
  DEFAULT_FAULT_PROFILE,
  type ChaosPreset,
  type ChaosTab,
} from "./components/chaos/ChaosControls";
import type { LabRouting } from "./components/inspector/LabPanel";
import { TargetInspector } from "./components/inspector/TargetInspector";
import { CommandPalette, type PaletteCommand } from "./components/shell/CommandPalette";
import { TabStrip } from "./components/shell/PanelHeader";
import { StatusBar } from "./components/shell/StatusBar";
import { Toolbar } from "./components/shell/Toolbar";
import { Workspace } from "./components/shell/Workspace";
import { EventInspector, EventRaw } from "./components/telemetry/EventInspector";
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
import { TELEMETRY_CAPACITY, useTelemetry } from "./hooks/useTelemetry";
import { routeContracts } from "./lib/contract";
import type { AuditKind } from "./lib/traffic";
import { ipcAvailable } from "./lib/ipc";
import { originOf, withHeaders, type RequestOrigin } from "./lib/request";
import { AUTO_TARGET } from "./lib/risk";
import { toBurstMethod, type RequestTarget } from "./lib/routes";
import { DEFAULT_LISTEN_PORT } from "./lib/rules";
import type { DiscoveredRoute, FaultProfile, HeaderPair, RouteRiskKind } from "./lib/types";

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
  const [burstHeaders, setBurstHeaders] = useState("");
  const [fuzzPayload, setFuzzPayload] = useState("");
  const [chaosPreset, setChaosPreset] = useState<ChaosPreset | null>(null);
  const [listenPort, setListenPort] = useState(DEFAULT_LISTEN_PORT);
  const [selectedSeq, setSelectedSeq] = useState<number | null>(null);
  const [detailTab, setDetailTab] = useState<DetailTab>("topology");

  const { status: proxyStatus, applyFaults, stop: stopProxy, applyContracts } = proxy;

  // The route list in view is the contract source: a project scan or the lab document
  // replaces the proxy's contract set, and a report without OpenAPI routes clears it.
  const routeReport = routeScan.report;
  useEffect(() => {
    if (!ipcAvailable || routeReport === null) return;
    applyContracts(routeContracts(routeReport.routes));
  }, [routeReport, applyContracts]);

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
  const filterRef = useRef<HTMLInputElement>(null);
  const inspectorRef = useRef<PanelImperativeHandle | null>(null);
  const chaosRef = useRef<PanelImperativeHandle | null>(null);
  const detailRef = useRef<PanelImperativeHandle | null>(null);

  // Auto-target: a static finding becomes a live test of the same handler. The route is
  // selected (method, path, sample body, contract) and the matching tab opens preset for the
  // finding's failure mode.
  const autoTarget = useCallback(
    (route: DiscoveredRoute, kind: RouteRiskKind) => {
      selectRoute(route);
      const plan = AUTO_TARGET[kind];
      setChaosPreset((current) => ({
        nonce: (current?.nonce ?? 0) + 1,
        burst: plan.tab === "burst" ? plan.burst : null,
        fuzz: plan.tab === "fuzzer" ? plan.fuzz : null,
      }));
      chaosRef.current?.expand();
      setChaosTab(plan.tab);
    },
    [selectRoute],
  );

  // Fuzz-to-burst escalation: the payload that broke one request is fired from N
  // pre-connected workers, which separates a deterministic crash from one that only
  // surfaces under contention.
  const replayInBurst = useCallback((target: RequestTarget, body: string, origin: string, headers: HeaderPair[]) => {
    setRequestTarget(target);
    setBurstBody(body);
    setBurstOrigin(origin);
    // A header case's override replaces the line of the same name; the operator's other
    // headers (credentials, tracing) stay.
    if (headers.length > 0) setBurstHeaders((current) => withHeaders(current, headers));
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
    void routeProxyTo(labBaseUrl, listenPort).then((status) => {
      if (status === null) return;
      setViaProxy(true);
      if (targetInput === labBaseUrl) {
        chaosRef.current?.expand();
      } else {
        loadLabTarget();
      }
    });
  }, [labBaseUrl, routeProxyTo, listenPort, targetInput, loadLabTarget]);
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
    burstRuns: burst.bySync,
    fuzz: fuzzer.report,
    traffic: telemetry.audit,
    routes: routeScan.report,
  });
  const { save: saveReport, copy: copyReport } = audit;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!(e.ctrlKey || e.metaKey)) return;
      const key = e.key.toLowerCase();
      if (key === "k") {
        e.preventDefault();
        setPaletteOpen((open) => !open);
      } else if (key === "f") {
        e.preventDefault();
        filterRef.current?.select();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const { setPaused, paused, clear, setFilter: setTelemetryFilter } = telemetry;
  const showAudit = useCallback(
    (kind: AuditKind | null) => {
      setTelemetryFilter({ kind: "findings", audit: kind });
    },
    [setTelemetryFilter],
  );
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
      { id: "filter", group: "Events", label: "Filter events", icon: ListFilter, shortcut: "Ctrl F", run: () => filterRef.current?.select() },
      { id: "pause", group: "Events", label: paused ? "Resume capture" : "Pause capture", icon: Pause, run: () => setPaused(!paused) },
      { id: "clear", group: "Events", label: "Clear event buffer", icon: Trash2, run: clear },
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
      { id: "toggle-inspector", group: "Layout", label: "Toggle target sidebar", icon: PanelLeft, run: toggle(inspectorRef) },
      { id: "toggle-chaos", group: "Layout", label: "Toggle tools pane", icon: PanelRight, run: toggle(chaosRef) },
      { id: "toggle-detail", group: "Layout", label: "Toggle detail pane", icon: PanelBottom, run: toggle(detailRef) },
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

  const selectedEvent = useMemo(
    () => (selectedSeq === null ? null : (telemetry.events.find((e) => e.seq === selectedSeq) ?? null)),
    [selectedSeq, telemetry.events],
  );
  const selectEvent = useCallback((seq: number) => {
    setSelectedSeq(seq);
    setDetailTab((tab) => (tab === "topology" ? "event" : tab));
  }, []);

  return (
    <div className="flex h-full flex-col bg-panel text-fg">
      <Toolbar
        online={link.state === "online"}
        proxy={proxy}
        upstream={validated}
        listenPort={listenPort}
        faultProfile={faultProfile}
        paused={paused}
        onTogglePause={() => setPaused(!paused)}
        onClear={() => {
          clear();
          setSelectedSeq(null);
        }}
        lab={lab}
        onLoadLab={loadLabTarget}
        exportBusy={audit.busy}
        notice={audit.notice}
        onExport={saveReport}
        onCopyReport={copyReport}
        onOpenPalette={() => setPaletteOpen(true)}
      />

      <Workspace
        panelRefs={{ sidebar: inspectorRef, tools: chaosRef, detail: detailRef }}
        sidebar={
          <TargetInspector
            input={targetInput}
            onInput={setTargetInput}
            guard={guard}
            link={link}
            inputRef={targetRef}
            scan={routeScan}
            selectedRoute={selectedRoute}
            onSelectRoute={selectRoute}
            onAutoTarget={autoTarget}
            lab={lab}
            onLoadLab={loadLabTarget}
            labRouting={labRouting}
            onRouteViaProxy={routeViaProxy}
            onRouteDirect={routeDirect}
          />
        }
        traffic={<TelemetryTable store={telemetry} selected={selectedSeq} onSelect={selectEvent} queryRef={filterRef} />}
        detail={
          <div className="flex h-full flex-col bg-bg">
            <TabStrip
              label="Detail"
              value={detailTab}
              onChange={setDetailTab}
              tabs={[
                { id: "event", label: "Inspector" },
                { id: "raw", label: "Raw" },
                { id: "topology", label: "Topology" },
              ]}
            />
            <div className="min-h-0 flex-1">
              {detailTab === "event" && <EventInspector event={selectedEvent} />}
              {detailTab === "raw" && <EventRaw event={selectedEvent} />}
              {detailTab === "topology" && (
                <TopologyCanvas link={link} guard={guard} proxy={proxyStatus} route={selectedRoute} fuzz={endpointFuzz} />
              )}
            </div>
          </div>
        }
        tools={
          <ChaosControls
            tab={chaosTab}
            onTab={setChaosTab}
            profile={faultProfile}
            onChange={setFaultProfile}
            link={link}
            guard={guard}
            requestOrigin={requestOrigin}
            proxy={proxy}
            listenPort={listenPort}
            onListenPort={setListenPort}
            burst={burst}
            fuzzer={fuzzer}
            fuzzerProgress={telemetry.fuzzerProgress}
            target={requestTarget}
            onTarget={setRequestTarget}
            burstBody={burstBody}
            onBurstBody={editBurstBody}
            burstHeaders={burstHeaders}
            onBurstHeaders={setBurstHeaders}
            fuzzPayload={fuzzPayload}
            onFuzzPayload={setFuzzPayload}
            sampleBody={selectedRoute?.sampleBody ?? null}
            route={selectedRoute}
            burstOrigin={burstOrigin}
            onReplayInBurst={replayInBurst}
            audit={telemetry.audit}
            onAuditFilter={showAudit}
            preset={chaosPreset}
          />
        }
      />

      <StatusBar
        link={link}
        proxy={proxyStatus}
        paused={paused}
        buffered={telemetry.events.length}
        capacity={TELEMETRY_CAPACITY}
        received={telemetry.totalReceived}
        viaProxy={requestOrigin?.via != null}
      />
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} commands={commands} />
    </div>
  );
}

type DetailTab = "event" | "raw" | "topology";
