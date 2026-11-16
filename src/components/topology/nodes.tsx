import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import type { LucideIcon } from "lucide-react";
import { TONE_BG, TONE_TEXT, type Tone } from "../../lib/tone";
import { StatusDot } from "../shell/PanelHeader";

export type TopoNodeData = {
  title: string;
  role: string;
  icon: LucideIcon;
  tone: Tone;
  state: string;
  /** Key, value, and an optional semantic tone for the value. */
  lines: ReadonlyArray<readonly [string, string, Tone?]>;
  inbound: boolean;
  outbound: boolean;
};

export type TopoNode = Node<TopoNodeData, "topo">;

export function TopoNodeView({ data, selected }: NodeProps<TopoNode>) {
  const Icon = data.icon;
  return (
    <div
      className={`w-[196px] overflow-hidden rounded-xs border bg-bg text-xs ${
        selected ? "border-accent" : "border-line-strong"
      }`}
    >
      <div className="flex h-[26px] items-center gap-1.5 border-b border-line bg-panel px-2">
        <Icon size={13} strokeWidth={1.75} className="shrink-0 text-fg-dim" />
        <span className="truncate font-semibold text-fg-bright">{data.title}</span>
        <span className={`num ml-auto flex items-center gap-1 text-2xs ${TONE_TEXT[data.tone]}`}>
          <StatusDot className={TONE_BG[data.tone]} />
          {data.state}
        </span>
      </div>
      <div className="px-2 py-1.5">
        <div className="mb-1 text-2xs text-fg-faint">{data.role}</div>
        <dl className="grid grid-cols-[auto_1fr] gap-x-2">
          {data.lines.map(([k, v, tone]) => (
            <div key={k} className="contents">
              <dt className="text-fg-faint">{k}</dt>
              <dd className={`num truncate text-right ${tone === undefined ? "text-fg" : TONE_TEXT[tone]}`} title={v}>
                {v}
              </dd>
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
