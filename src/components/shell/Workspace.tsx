import type { ReactNode, Ref } from "react";
import { Group, Panel, Separator, type PanelImperativeHandle } from "react-resizable-panels";

export interface WorkspacePanelRefs {
  sidebar: Ref<PanelImperativeHandle | null>;
  tools: Ref<PanelImperativeHandle | null>;
  detail: Ref<PanelImperativeHandle | null>;
}

interface WorkspaceProps {
  panelRefs: WorkspacePanelRefs;
  sidebar: ReactNode;
  traffic: ReactNode;
  detail: ReactNode;
  tools: ReactNode;
}

/**
 * Source list | event list over detail | tool notebook. The list owns the centre, as in
 * every capture tool; the detail pane follows the selection below it.
 */
export function Workspace({ panelRefs, sidebar, traffic, detail, tools }: WorkspaceProps) {
  return (
    <Group orientation="horizontal" className="min-h-0 flex-1">
      <Panel id="sidebar" panelRef={panelRefs.sidebar} defaultSize="21%" minSize={240} collapsible>
        {sidebar}
      </Panel>
      <Separator />
      <Panel id="centre" minSize="30%">
        <Group orientation="vertical" className="h-full">
          <Panel id="traffic" defaultSize="58%" minSize={140}>
            {traffic}
          </Panel>
          <Separator />
          <Panel id="detail" panelRef={panelRefs.detail} defaultSize="42%" minSize={120} collapsible>
            {detail}
          </Panel>
        </Group>
      </Panel>
      <Separator />
      <Panel id="tools" panelRef={panelRefs.tools} defaultSize="25%" minSize={290} collapsible>
        {tools}
      </Panel>
    </Group>
  );
}
