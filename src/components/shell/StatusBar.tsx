import type { EngineLink } from "../../hooks/useEngineStatus";
import { formatUptime } from "../../lib/format";
import { Kbd, StatusSquare } from "./PanelHeader";

export function StatusBar({ link }: { link: EngineLink }) {
  const online = link.state === "online";
  const label = online ? "ENGINE ONLINE" : link.state === "connecting" ? "CONNECTING" : "ENGINE OFFLINE";
  const tone = online ? "bg-ok" : link.state === "connecting" ? "bg-muted" : "bg-fault";

  return (
    <footer className="num flex h-[22px] shrink-0 items-center gap-4 border-t border-line bg-panel px-2.5 text-2xs text-fg-dim">
      <span className="flex items-center gap-1.5 font-medium text-fg">
        <StatusSquare className={tone} />
        {label}
      </span>
      {online ? (
        <>
          <Item k="uptime" v={formatUptime(link.status.uptimeMs)} />
          <Item k="subs" v={String(link.status.telemetrySubscribers)} />
          <Item k="guard" v={link.status.guardMode} />
          <Item k="proxy" v={link.status.proxyListener ?? "offline"} />
        </>
      ) : link.state === "unavailable" ? (
        <span className="text-fg-faint">{link.reason}</span>
      ) : null}
      <span className="ml-auto flex items-center gap-4">
        <span className="flex items-center gap-1 text-fg-faint">
          <Kbd>Ctrl</Kbd>
          <Kbd>K</Kbd>
          <span>commands</span>
        </span>
        <span className="text-fg-faint">v{online ? link.status.version : "-"}</span>
      </span>
    </footer>
  );
}

function Item({ k, v }: { k: string; v: string }) {
  return (
    <span>
      <span className="text-fg-faint">{k} </span>
      {v}
    </span>
  );
}
