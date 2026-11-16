import type { EngineLink } from "../../hooks/useEngineStatus";
import { formatCount, formatUptime } from "../../lib/format";
import type { ProxyStatus } from "../../lib/types";
import { StatusDot } from "./PanelHeader";

interface StatusBarProps {
  link: EngineLink;
  proxy: ProxyStatus | null;
  paused: boolean;
  buffered: number;
  capacity: number;
  received: number;
  viaProxy: boolean;
}

/** Counters and active engine options, in the order a capture tool's status bar lists them. */
export function StatusBar({ link, proxy, paused, buffered, capacity, received, viaProxy }: StatusBarProps) {
  const online = link.state === "online";
  const label = online ? "Engine online" : link.state === "connecting" ? "Connecting" : "Engine offline";
  const tone = online ? "bg-ok" : link.state === "connecting" ? "bg-muted" : "bg-fault";
  const listening = proxy?.running === true;

  return (
    <footer className="flex h-[22px] shrink-0 items-center gap-3 overflow-hidden whitespace-nowrap border-t border-line bg-panel px-2.5 text-xs text-fg-dim">
      <span className="flex items-center gap-1.5 text-fg">
        <StatusDot className={tone} />
        {label}
      </span>
      <Divider />
      <span className="num">
        Events: {formatCount(received)} <span className="text-fg-faint">·</span> Buffered: {formatCount(buffered)}/
        {formatCount(capacity)}
      </span>
      <Divider />
      <span className="num">{listening ? `Listening ${proxy?.listener ?? "-"}` : "Proxy stopped"}</span>
      <div className="flex items-center gap-1">
        {paused && <Pill tone="warn">capture_paused</Pill>}
        {proxy?.armed === true && <Pill tone="warn">faults_armed</Pill>}
        {(proxy?.rules.length ?? 0) > 0 && <Pill tone="neutral">{`route_rules=${proxy?.rules.length ?? 0}`}</Pill>}
        {(proxy?.contracts ?? 0) > 0 && <Pill tone="neutral">{`contracts=${proxy?.contracts ?? 0}`}</Pill>}
        {viaProxy && <Pill tone="neutral">via_proxy</Pill>}
      </div>
      {link.state === "unavailable" && <span className="min-w-0 truncate text-fg-faint">{link.reason}</span>}
      <span className="num ml-auto flex items-center gap-3 text-fg-faint">
        {online && (
          <>
            <span>guard {link.status.guardMode}</span>
            <span>up {formatUptime(link.status.uptimeMs)}</span>
          </>
        )}
        <span>z-proxy {online ? link.status.version : ""}</span>
      </span>
    </footer>
  );
}

function Divider() {
  return <span className="h-3 w-px bg-line-strong" aria-hidden />;
}

function Pill({ tone, children }: { tone: "warn" | "neutral"; children: string }) {
  return (
    <span
      className={`num rounded-xs border px-1 text-2xs leading-[14px] ${
        tone === "warn" ? "border-warn/60 bg-warn/12 text-fg" : "border-line-strong bg-control text-fg-dim"
      }`}
    >
      {children}
    </span>
  );
}
