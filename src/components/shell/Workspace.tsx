import type { ReactNode, Ref } from "react";
import { Group, Panel, Separator, type PanelImperativeHandle } from "react-resizable-panels";

export interface WorkspacePanelRefs {
  inspector: Ref<PanelImperativeHandle | null>;
  chaos: Ref<PanelImperativeHandle | null>;
  telemetry: Ref<PanelImperativeHandle | null>;
}

interface WorkspaceProps {
  panelRefs: WorkspacePanelRefs;
  inspector: ReactNode;
  topology: ReactNode;
  chaos: ReactNode;
  telemetry: ReactNode;
}

export function Workspace({ panelRefs, inspector, topology, chaos, telemetry }: WorkspaceProps) {
  return (
    <Group orientation="vertical" className="min-h-0 flex-1">
      <Panel id="workbench" defaultSize="66%" minSize="30%">
        <Group orientation="horizontal" className="h-full">
          <Panel id="inspector" panelRef={panelRefs.inspector} defaultSize="22%" minSize={240} collapsible>
            {inspector}
          </Panel>
          <Separator />
          <Panel id="topology" minSize="25%">
            {topology}
          </Panel>
          <Separator />
          <Panel id="chaos" panelRef={panelRefs.chaos} defaultSize="24%" minSize={260} collapsible>
            {chaos}
          </Panel>
        </Group>
      </Panel>
      <Separator />
      <Panel id="telemetry" panelRef={panelRefs.telemetry} defaultSize="34%" minSize={120} collapsible>
        {telemetry}
      </Panel>
    </Group>
  );
}
