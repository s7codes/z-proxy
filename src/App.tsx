import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { PanelImperativeHandle } from "react-resizable-panels";
import {
  CircleStop,
  Crosshair,
  FlaskConical,
  FolderOpen,
  PanelBottom,
  PanelLeft,
  PanelRight,
  Pause,
  Power,
  RefreshCw,
  RotateCcw,
  Square,
  Trash2,
} from "lucide-react";
import { ChaosControls, DEFAULT_FAULT_PROFILE, type ChaosTab } from "./components/chaos/ChaosControls";
import { TargetInspector } from "./components/inspector/TargetInspector";
import { CommandPalette, type PaletteCommand } from "./components/shell/CommandPalette";
import { Kbd } from "./components/shell/PanelHeader";
import { StatusBar } from "./components/shell/StatusBar";
import { Workspace } from "./components/shell/Workspace";
import { TelemetryTable } from "./components/telemetry/TelemetryTable";
import { TopologyCanvas } from "./components/topology/TopologyCanvas";
import { useBurst } from "./hooks/useBurst";
import { useEngineStatus } from "./hooks/useEngineStatus";
import { useFuzzer } from "./hooks/useFuzzer";
import { useGuardValidator } from "./hooks/useGuardValidator";
import { sameProfile, useProxy } from "./hooks/useProxy";
import { useRouteScan } from "./hooks/useRouteScan";
import { useTelemetry } from "./hooks/useTelemetry";
import { toBurstMethod, type RequestTarget } from "./lib/routes";
import type { DiscoveredRoute, FaultProfile } from "./lib/types";

// Slider drags emit a value per pixel; one IPC round trip per settled position is enough.
const PROFILE_PUSH_MS = 150;

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
  const [chaosTab, setChaosTab] = useState<ChaosTab>("faults");
  const [selectedRoute, setSelectedRoute] = useState<DiscoveredRoute | null>(null);
  const [requestTarget, setRequestTarget] = useState<RequestTarget>({ method: "POST", path: "/" });
  // Payloads live here rather than in the panels so a route selection (OpenAPI sample) and
  // later a fuzz finding can write them while the owning tab is not mounted.
  const [burstBody, setBurstBody] = useState("");
  const [fuzzPayload, setFuzzPayload] = useState("");

  const { status: proxyStatus, applyFaults, stop: stopProxy } = proxy;

  const selectRoute = useCallback((route: DiscoveredRoute) => {
    setSelectedRoute(route);
    setRequestTarget((current) => ({ method: toBurstMethod(route.method) ?? current.method, path: route.path }));
    if (route.sampleBody !== null) {
      setBurstBody(route.sampleBody);
      setFuzzPayload(route.sampleBody);
    }
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
  const commands = useMemo<PaletteCommand[]>(() => {
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
      { id: "toggle-inspector", group: "Layout", label: "Toggle inspector panel", icon: PanelLeft, run: toggle(inspectorRef) },
      { id: "toggle-chaos", group: "Layout", label: "Toggle chaos panel", icon: PanelRight, run: toggle(chaosRef) },
      { id: "toggle-telemetry", group: "Layout", label: "Toggle telemetry panel", icon: PanelBottom, run: toggle(telemetryRef) },
    ];
  }, [
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
  ]);

  // The endpoint node reflects the last fuzz report only while it still describes the
  // request path the panels target.
  const endpointFuzz = useMemo(() => {
    const report = fuzzer.report;
    if (report === null) return null;
    try {
      return new URL(report.target).pathname === requestTarget.path ? report : null;
    } catch {
      return null;
    }
  }, [fuzzer.report, requestTarget.path]);

  return (
    <div className="flex h-full flex-col bg-bg text-fg">
      <header className="flex h-8 shrink-0 items-center gap-3 border-b border-line bg-panel px-2.5">
        <span className="text-sm font-semibold tracking-tight text-fg-bright">ChaosProxy</span>
        <span className="h-3.5 w-px bg-line" />
        <span className="text-xs text-fg-dim">workspace</span>
        <span className="num text-xs text-fg">local</span>
        <button
          type="button"
          onClick={() => setPaletteOpen(true)}
          className="ml-auto flex h-5 w-64 items-center gap-2 rounded-xs border border-line bg-bg px-2 text-xs text-fg-faint hover:border-line-strong"
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
            proxy={proxy}
            burst={burst}
            fuzzer={fuzzer}
            fuzzerProgress={telemetry.fuzzerProgress}
            target={requestTarget}
            onTarget={setRequestTarget}
            burstBody={burstBody}
            onBurstBody={setBurstBody}
            fuzzPayload={fuzzPayload}
            onFuzzPayload={setFuzzPayload}
            sampleBody={selectedRoute?.sampleBody ?? null}
            route={selectedRoute}
          />
        }
        telemetry={<TelemetryTable store={telemetry} />}
      />

      <StatusBar link={link} />
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} commands={commands} />
    </div>
  );
}
