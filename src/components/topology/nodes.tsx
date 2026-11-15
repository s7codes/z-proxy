import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import type { LucideIcon } from "lucide-react";
import { TONE_BG, TONE_TEXT, type Tone } from "../../lib/tone";
import { StatusSquare } from "../shell/PanelHeader";

export type TopoNodeData = {
  title: string;
  role: string;
  icon: LucideIcon;
  tone: Tone;
  state: string;
  lines: ReadonlyArray<readonly [string, string]>;
  inbound: boolean;
  outbound: boolean;
};

export type TopoNode = Node<TopoNodeData, "topo">;

export function TopoNodeView({ data, selected }: NodeProps<TopoNode>) {
  const Icon = data.icon;
  return (
    <div
      className={`w-[188px] border bg-panel text-xs ${selected ? "border-fg-faint" : "border-line"}`}
    >
      <div className="flex h-6 items-center gap-1.5 border-b border-line px-2">
        <Icon size={12} strokeWidth={1.5} className="shrink-0 text-fg-dim" />
        <span className="truncate font-medium text-fg-bright">{data.title}</span>
        <span className={`num ml-auto flex items-center gap-1 text-2xs ${TONE_TEXT[data.tone]}`}>
          <StatusSquare className={TONE_BG[data.tone]} />
          {data.state}
        </span>
      </div>
      <div className="px-2 py-1.5">
        <div className="label-caps mb-1 text-fg-faint">{data.role}</div>
        <dl className="grid grid-cols-[auto_1fr] gap-x-2">
          {data.lines.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-fg-faint">{k}</dt>
              <dd className="num truncate text-right text-fg">{v}</dd>
            </div>
          ))}
        </dl>
      </div>
      {/* Both handles always mount: React Flow registers handles when a node is measured, so
          one added later (the upstream outlet once a route is selected) would leave its edge
          unrendered. Unused handles are hidden instead. */}
      <Handle type="target" position={Position.Left} isConnectable={false} className={data.inbound ? "" : "invisible"} />
      <Handle type="source" position={Position.Right} isConnectable={false} className={data.outbound ? "" : "invisible"} />
    </div>
  );
}

export const nodeTypes = { topo: TopoNodeView };
