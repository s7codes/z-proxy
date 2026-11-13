import { useMemo } from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  MarkerType,
  ReactFlow,
  useNodesState,
  type Edge,
} from "@xyflow/react";
import { Cpu, MonitorDot, Server, ShieldCheck } from "lucide-react";
import type { EngineLink } from "../../hooks/useEngineStatus";
import type { GuardState } from "../../hooks/useGuardValidator";
import { formatLatency } from "../../lib/format";
import { guardTone, TONE_HEX, type Tone } from "../../lib/tone";
import { PanelHeader } from "../shell/PanelHeader";
import { nodeTypes, type TopoNode, type TopoNodeData } from "./nodes";

interface TopologyCanvasProps {
  link: EngineLink;
  guard: GuardState;
}

type NodeId = "client" | "engine" | "guard" | "upstream";

const POSITIONS: Record<NodeId, { x: number; y: number }> = {
  client: { x: 0, y: 40 },
  engine: { x: 260, y: 40 },
  guard: { x: 520, y: 40 },
  upstream: { x: 780, y: 40 },
};

const INITIAL_NODES: TopoNode[] = (Object.keys(POSITIONS) as NodeId[]).map((id) => ({
  id,
  type: "topo",
  position: POSITIONS[id],
  data: placeholderData(id),
}));

export function TopologyCanvas({ link, guard }: TopologyCanvasProps) {
  const [nodes, , onNodesChange] = useNodesState<TopoNode>(INITIAL_NODES);

  const dataById = useMemo(() => buildNodeData(link, guard), [link, guard]);
  const displayNodes = useMemo(
    () => nodes.map((n) => ({ ...n, data: dataById[n.id as NodeId] })),
    [nodes, dataById],
  );
  const edges = useMemo(() => buildEdges(link, guard), [link, guard]);

  return (
    <div className="flex h-full flex-col">
      <PanelHeader title="Topology" meta="4 nodes / 3 links" />
      <div className="relative min-h-0 flex-1">
        <ReactFlow<TopoNode, Edge>
          nodes={displayNodes}
          edges={edges}
          onNodesChange={onNodesChange}
          nodeTypes={nodeTypes}
          nodesConnectable={false}
          edgesFocusable={false}
          fitView
          fitViewOptions={{ padding: 0.25, maxZoom: 1 }}
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

function buildNodeData(link: EngineLink, guard: GuardState): Record<NodeId, TopoNodeData> {
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
      tone: engineTone,
      state: online ? "RUNNING" : link.state === "connecting" ? "CONNECTING" : "OFFLINE",
      lines: [
        ["version", online ? link.status.version : "-"],
        ["subscribers", online ? String(link.status.telemetrySubscribers) : "-"],
        ["proxy", online && link.status.proxyListener !== null ? link.status.proxyListener : "offline"],
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
    },
  };
}

function buildEdges(link: EngineLink, guard: GuardState): Edge[] {
  const online = link.state === "online";
  const tone = guardTone(guard);
  const ipcTone: Tone = online ? "ok" : "muted";

  return [
    edge("client", "engine", ipcTone, online ? "invoke / channel" : undefined),
    edge("engine", "guard", ipcTone, undefined),
    edge("guard", "upstream", tone, upstreamEdgeLabel(guard), guard.phase === "rejected"),
  ];
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
  }
}
