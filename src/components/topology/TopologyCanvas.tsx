import { useEffect, useMemo, useRef } from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  MarkerType,
  ReactFlow,
  useNodesState,
  type Edge,
  type FitViewOptions,
  type ReactFlowInstance,
} from "@xyflow/react";
import { Cpu, MonitorDot, Route, Server, ShieldCheck } from "lucide-react";
import type { EngineLink } from "../../hooks/useEngineStatus";
import type { GuardState } from "../../hooks/useGuardValidator";
import { formatLatency } from "../../lib/format";
import { fileLabel, SOURCE_LABEL } from "../../lib/routes";
import type { DiscoveredRoute, FuzzReport, ProxyStatus } from "../../lib/types";
import { guardTone, TONE_HEX, type Tone } from "../../lib/tone";
import { PanelHeader } from "../shell/PanelHeader";
import { nodeTypes, type TopoNode, type TopoNodeData } from "./nodes";

interface TopologyCanvasProps {
  link: EngineLink;
  guard: GuardState;
  proxy: ProxyStatus | null;
  route: DiscoveredRoute | null;
  /** Last fuzz report for the targeted path, if any. */
  fuzz: FuzzReport | null;
}

const FIT_VIEW: FitViewOptions = { padding: 0.25, maxZoom: 1 };

type NodeId = "client" | "engine" | "guard" | "upstream" | "endpoint";

const POSITIONS: Record<NodeId, { x: number; y: number }> = {
  client: { x: 0, y: 40 },
  engine: { x: 260, y: 40 },
  guard: { x: 520, y: 40 },
  upstream: { x: 780, y: 40 },
  endpoint: { x: 1040, y: 40 },
};

const INITIAL_NODES: TopoNode[] = (Object.keys(POSITIONS) as NodeId[]).map((id) => ({
  id,
  type: "topo",
  position: POSITIONS[id],
  data: placeholderData(id),
}));

export function TopologyCanvas({ link, guard, proxy, route, fuzz }: TopologyCanvasProps) {
  const [nodes, , onNodesChange] = useNodesState<TopoNode>(INITIAL_NODES);
  const containerRef = useRef<HTMLDivElement>(null);
  const flowRef = useRef<ReactFlowInstance<TopoNode, Edge> | null>(null);

  // React Flow tracks its container size but keeps the old viewport, so a panel resize
  // leaves the graph clipped or stranded in a corner. Refit once per frame at most.
  useEffect(() => {
    const container = containerRef.current;
    if (container === null) return;
    let frame = 0;
    const observer = new ResizeObserver((entries) => {
      const rect = entries[entries.length - 1]?.contentRect;
      if (rect === undefined || rect.width === 0 || rect.height === 0) return;
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        void flowRef.current?.fitView(FIT_VIEW);
      });
    });
    observer.observe(container);
    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
    };
  }, []);

  // The endpoint node appears and disappears with the route selection; refit so it is not
  // left outside the viewport.
  const hasRoute = route !== null;
  useEffect(() => {
    const frame = requestAnimationFrame(() => {
      void flowRef.current?.fitView(FIT_VIEW);
    });
    return () => cancelAnimationFrame(frame);
  }, [hasRoute]);

  const dataById = useMemo(
    () => buildNodeData(link, guard, proxy, route, fuzz),
    [link, guard, proxy, route, fuzz],
  );
  const displayNodes = useMemo(
    () => nodes.map((n) => ({ ...n, hidden: n.id === "endpoint" && !hasRoute, data: dataById[n.id as NodeId] })),
    [nodes, dataById, hasRoute],
  );
  const edges = useMemo(() => buildEdges(link, guard, proxy, route), [link, guard, proxy, route]);

  return (
    <div className="flex h-full flex-col">
      <PanelHeader title="Topology" meta={`${hasRoute ? 5 : 4} nodes / ${edges.length} links`} />
      <div ref={containerRef} className="relative min-h-0 flex-1">
        <ReactFlow<TopoNode, Edge>
          nodes={displayNodes}
          edges={edges}
          onNodesChange={onNodesChange}
          nodeTypes={nodeTypes}
          nodesConnectable={false}
          edgesFocusable={false}
          onInit={(instance) => {
            flowRef.current = instance;
          }}
          fitView
          fitViewOptions={FIT_VIEW}
          minZoom={0.4}
          maxZoom={2}
          colorMode="dark"
          proOptions={{ hideAttribution: false }}
        >
          <Background variant={BackgroundVariant.Dots} gap={16} size={1} color="#1F2430" />
          <Controls showInteractive={false} position="bottom-left" />
        </ReactFlow>
      </div>
    </div>
  );
}

function buildNodeData(
  link: EngineLink,
  guard: GuardState,
  proxy: ProxyStatus | null,
  route: DiscoveredRoute | null,
  fuzz: FuzzReport | null,
): Record<NodeId, TopoNodeData> {
  const online = link.state === "online";
  const engineTone: Tone = online ? "ok" : link.state === "connecting" ? "muted" : "fault";
  const tone = guardTone(guard);

  return {
    client: {
      ...placeholderData("client"),
      tone: online ? "ok" : "muted",
      state: online ? "IPC" : "DETACHED",
    },
    engine: {
      ...placeholderData("engine"),
      tone: online && proxy?.armed === true ? "warn" : engineTone,
      state: online ? (proxy?.running === true ? "PROXYING" : "RUNNING") : link.state === "connecting" ? "CONNECTING" : "OFFLINE",
      lines: [
        ["version", online ? link.status.version : "-"],
        ["subscribers", online ? String(link.status.telemetrySubscribers) : "-"],
        ["proxy", proxy?.listener ?? "offline"],
        [
          "faults",
          proxy === null ? "-" : `${proxy.armed ? "armed" : "off"}${proxy.rules.length > 0 ? ` +${proxy.rules.length} rules` : ""}`,
        ],
      ],
    },
    guard: {
      ...placeholderData("guard"),
      tone: guard.phase === "rejected" ? "fault" : guard.phase === "accepted" ? "ok" : "muted",
      state: guard.phase === "rejected" ? "BLOCK" : guard.phase === "accepted" ? "PASS" : "IDLE",
      lines: [
        ["mode", "strict"],
        ["last", guard.phase === "rejected" ? shortCode(guard.error.code) : guard.phase === "accepted" ? "accepted" : "-"],
      ],
    },
    upstream: {
      ...placeholderData("upstream"),
      tone,
      state: upstreamState(guard),
      title:
        guard.phase === "accepted"
          ? `${guard.target.host}:${guard.target.port}`
          : guard.phase === "rejected"
            ? "rejected target"
            : guard.phase === "empty"
              ? "no target"
              : "unvalidated",
      lines: upstreamLines(guard),
      outbound: route !== null,
    },
    endpoint:
      route === null
        ? placeholderData("endpoint")
        : {
            ...placeholderData("endpoint"),
            title: route.path,
            tone: endpointTone(guard, fuzz),
            state: route.method,
            lines: [
              ["source", SOURCE_LABEL[route.source]],
              ["file", fileLabel(route.file, route.line)],
              ["params", route.params.length === 0 ? "-" : route.params.join(", ")],
              ["fuzz", fuzz === null ? "-" : `${fuzz.faults} fault / ${fuzz.cases.length}`],
            ],
          },
  };
}

function buildEdges(link: EngineLink, guard: GuardState, proxy: ProxyStatus | null, route: DiscoveredRoute | null): Edge[] {
  const online = link.state === "online";
  const proxying = online && proxy?.running === true;
  const tone = guardTone(guard);
  const ipcTone: Tone = online ? "ok" : "muted";

  const edges = [
    edge("client", "engine", ipcTone, online ? "invoke / channel" : undefined),
    edge("engine", "guard", ipcTone, proxying ? (proxy?.armed === true ? "proxy + faults" : "proxy") : undefined),
    edge("guard", "upstream", tone, upstreamEdgeLabel(guard), guard.phase === "rejected"),
  ];
  if (route !== null) {
    edges.push(edge("upstream", "endpoint", guard.phase === "accepted" ? "ok" : "muted", route.method));
  }
  return edges;
}

function edge(source: NodeId, target: NodeId, tone: Tone, label: string | undefined, dashed = false): Edge {
  const color = TONE_HEX[tone];
  const base: Edge = {
    id: `${source}-${target}`,
    source,
    target,
    type: "smoothstep",
    animated: false,
    style: { stroke: color, strokeWidth: 1, strokeDasharray: dashed ? "4 3" : undefined },
    markerEnd: { type: MarkerType.ArrowClosed, color, width: 14, height: 14 },
    labelStyle: { fill: color },
    labelBgStyle: { fill: "#090A0D" },
    labelBgPadding: [4, 2],
    labelBgBorderRadius: 0,
  };
  return label === undefined ? base : { ...base, label };
}

function endpointTone(guard: GuardState, fuzz: FuzzReport | null): Tone {
  if (fuzz !== null && fuzz.faults > 0) return "fault";
  if (fuzz !== null && fuzz.warnings > 0) return "warn";
  return guard.phase === "accepted" ? "ok" : "muted";
}

function upstreamEdgeLabel(guard: GuardState): string | undefined {
  switch (guard.phase) {
    case "accepted":
      return guard.target.probe.state === "reachable"
        ? `HEAD ${guard.target.probe.status}  ${formatLatency(guard.target.probe.latencyUs)}`
        : guard.target.probe.reason;
    case "rejected":
      return "NON-LOOPBACK";
    default:
      return undefined;
  }
}

function upstreamState(guard: GuardState): string {
  switch (guard.phase) {
    case "empty":
      return "UNSET";
    case "offline":
      return "UNKNOWN";
    case "pending":
      return "PROBING";
    case "rejected":
      return "DENIED";
    case "accepted":
      return guard.target.probe.state === "reachable" ? "REACHABLE" : "DOWN";
  }
}

function upstreamLines(guard: GuardState): ReadonlyArray<readonly [string, string]> {
  if (guard.phase === "accepted") {
    const { target } = guard;
    return [
      ["scheme", target.scheme],
      ["kind", target.hostKind],
      ["rtt", formatLatency(target.probe.latencyUs)],
    ];
  }
  if (guard.phase === "rejected") {
    return [["host", "host" in guard.error ? guard.error.host : "-"]];
  }
  return [["host", "-"]];
}

function shortCode(code: string): string {
  return code.toLowerCase().replaceAll("_", "-");
}

function placeholderData(id: NodeId): TopoNodeData {
  switch (id) {
    case "client":
      return {
        title: "WebView",
        role: "operator ui",
        icon: MonitorDot,
        tone: "muted",
        state: "DETACHED",
        lines: [["transport", "tauri ipc"]],
        inbound: false,
        outbound: true,
      };
    case "engine":
      return {
        title: "Engine",
        role: "tokio runtime",
        icon: Cpu,
        tone: "muted",
        state: "CONNECTING",
        lines: [],
        inbound: true,
        outbound: true,
      };
    case "guard":
      return {
        title: "Loopback Guard",
        role: "egress filter",
        icon: ShieldCheck,
        tone: "muted",
        state: "IDLE",
        lines: [],
        inbound: true,
        outbound: true,
      };
    case "upstream":
      return {
        title: "no target",
        role: "upstream",
        icon: Server,
        tone: "muted",
        state: "UNSET",
        lines: [],
        inbound: true,
        outbound: false,
      };
    case "endpoint":
      return {
        title: "no route",
        role: "endpoint",
        icon: Route,
        tone: "muted",
        state: "-",
        lines: [],
        inbound: true,
        outbound: false,
      };
  }
}
