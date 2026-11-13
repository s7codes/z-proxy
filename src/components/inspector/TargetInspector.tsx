import type { Ref } from "react";
import type { GuardState } from "../../hooks/useGuardValidator";
import type { EngineLink } from "../../hooks/useEngineStatus";
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
}

export function TargetInspector({ input, onInput, guard, link, inputRef }: TargetInspectorProps) {
  const allowlist = link.state === "online" ? link.status.allowlist : FALLBACK_ALLOWLIST;

  return (
    <div className="flex h-full flex-col bg-panel">
      <PanelHeader title="Target & Routes" />
      <div className="min-h-0 flex-1 overflow-y-auto">
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

        <Section title="Routes" aside={<span className="num text-2xs text-fg-faint">0</span>}>
          <RouteList />
        </Section>
      </div>
    </div>
  );
}
