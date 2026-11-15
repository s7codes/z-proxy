import type { Ref } from "react";
import type { EngineLink } from "../../hooks/useEngineStatus";
import type { GuardState } from "../../hooks/useGuardValidator";
import type { RouteScanControl } from "../../hooks/useRouteScan";
import type { DiscoveredRoute } from "../../lib/types";
import { PanelHeader, Section } from "../shell/PanelHeader";
import { GuardValidator } from "./GuardValidator";
import { RouteList } from "./RouteList";

const FALLBACK_ALLOWLIST = ["127.0.0.1", "::1", "localhost"] as const;

interface TargetInspectorProps {
  input: string;
  onInput: (value: string) => void;
  guard: GuardState;
  link: EngineLink;
  inputRef: Ref<HTMLInputElement>;
  scan: RouteScanControl;
  selectedRoute: DiscoveredRoute | null;
  onSelectRoute: (route: DiscoveredRoute) => void;
}

export function TargetInspector({
  input,
  onInput,
  guard,
  link,
  inputRef,
  scan,
  selectedRoute,
  onSelectRoute,
}: TargetInspectorProps) {
  const online = link.state === "online";
  const allowlist = online ? link.status.allowlist : FALLBACK_ALLOWLIST;

  return (
    <div className="flex h-full flex-col bg-panel">
      <PanelHeader title="Target & Routes" />
      <div className="shrink-0">
        <Section title="Loopback Guard" aside={<span className="num text-2xs text-fg-faint">strict</span>}>
          <GuardValidator value={input} onChange={onInput} state={guard} inputRef={inputRef} />
        </Section>

        <Section title="Allowlist" aside={<span className="num text-2xs text-fg-faint">exact match</span>}>
          <ul className="flex flex-col">
            {allowlist.map((host) => (
              <li
                key={host}
                className="num flex h-5 items-center justify-between border-b border-line/60 text-xs last:border-b-0"
              >
                <span className="text-fg">{host}</span>
                <span className="text-2xs text-fg-faint">{host === "localhost" ? "pinned 127.0.0.1" : "literal"}</span>
              </li>
            ))}
          </ul>
        </Section>
      </div>

      {/* The route list owns the remaining height and scrolls on its own, so a large project
          never pushes the guard input out of view. */}
      <section className="flex min-h-0 flex-1 flex-col">
        <div className="flex h-6 shrink-0 items-center px-2.5">
          <span className="label-caps text-fg-faint">Routes</span>
          <span className="num ml-auto text-2xs text-fg-faint">{scan.report?.routes.length ?? 0}</span>
        </div>
        <RouteList scan={scan} selected={selectedRoute} onSelect={onSelectRoute} online={online} />
      </section>
    </div>
  );
}
