import { useEffect, useRef, useState, type ReactNode } from "react";
import {
  ChevronDown,
  ClipboardCopy,
  Crosshair,
  FileDown,
  FlaskConical,
  Pause,
  Play,
  Power,
  Search,
  Square,
  Trash2,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import type { ExportNotice } from "../../hooks/useAuditExport";
import type { LabControl } from "../../hooks/useLab";
import type { ProxyControl } from "../../hooks/useProxy";
import { TONE_TEXT } from "../../lib/tone";
import type { FaultProfile } from "../../lib/types";
import { Kbd } from "./PanelHeader";

interface ToolbarProps {
  online: boolean;
  proxy: ProxyControl;
  upstream: string | null;
  listenPort: number;
  faultProfile: FaultProfile;
  paused: boolean;
  onTogglePause: () => void;
  onClear: () => void;
  lab: LabControl;
  onLoadLab: () => void;
  exportBusy: boolean;
  notice: ExportNotice | null;
  onExport: (format: "markdown" | "json") => void;
  onCopyReport: () => void;
  onOpenPalette: () => void;
}

/**
 * Main command bar. Commands that cannot run stay visible and disabled, so the bar never
 * reflows when engine state changes.
 */
export function Toolbar(props: ToolbarProps) {
  const { proxy, online, upstream, lab } = props;
  const running = proxy.status?.running === true;
  const armed = proxy.status?.armed === true;
  const labRunning = lab.status?.running === true;

  return (
    <header className="flex h-[38px] shrink-0 items-center gap-1 border-b border-line bg-panel px-2">
      <span className="mr-2 flex items-center gap-1.5 pl-0.5">
        <Logo />
        <span className="text-sm font-semibold text-fg-bright">z-proxy</span>
      </span>

      <Group>
        {running ? (
          <BarButton icon={Square} label="Stop proxy" disabled={proxy.busy} onClick={proxy.stop} iconClass="text-fault" />
        ) : (
          <BarButton
            icon={Play}
            label="Start proxy"
            disabled={!online || upstream === null || proxy.busy}
            title={upstream === null ? "Validate a loopback target first" : `Listen on 127.0.0.1:${props.listenPort} and forward to ${upstream}`}
            onClick={() => upstream !== null && proxy.start(upstream, props.listenPort)}
            iconClass="text-ok"
          />
        )}
        <BarButton
          icon={props.paused ? Play : Pause}
          label={props.paused ? "Resume" : "Pause"}
          pressed={props.paused}
          title={props.paused ? "Resume buffering engine events" : "Stop buffering engine events; counters keep running"}
          onClick={props.onTogglePause}
        />
        <BarButton icon={Trash2} label="Clear" title="Clear the event buffer" onClick={props.onClear} />
      </Group>

      <Group>
        <BarButton
          icon={Power}
          label={armed ? "Faults armed" : "Arm faults"}
          pressed={armed}
          tone={armed ? "warn" : undefined}
          disabled={!online || proxy.status === null}
          title={armed ? "Disarm: proxied traffic passes through unchanged" : "Apply the fault profile to proxied traffic"}
          onClick={() => proxy.applyFaults(!armed, props.faultProfile)}
        />
      </Group>

      <Group>
        {labRunning ? (
          <BarButton icon={Square} label="Stop lab" disabled={!online || lab.busy} onClick={lab.stop} />
        ) : (
          <BarButton
            icon={FlaskConical}
            label="Start lab"
            disabled={!online || lab.status === null || lab.busy}
            title="Start the embedded loopback target lab"
            onClick={() => lab.start(lab.status?.mode ?? "unprotected")}
          />
        )}
        <BarButton
          icon={Crosshair}
          label="Target lab"
          disabled={!labRunning}
          title="Validate the lab as target and list its routes"
          onClick={props.onLoadLab}
        />
      </Group>

      <div className="ml-auto flex min-w-0 items-center gap-2">
        {props.notice !== null && (
          <span className={`num min-w-0 truncate text-2xs ${TONE_TEXT[props.notice.tone]}`} title={props.notice.text} role="status">
            {props.notice.text}
          </span>
        )}
        <ExportMenu busy={props.exportBusy} onExport={props.onExport} onCopy={props.onCopyReport} />
        <button
          type="button"
          onClick={props.onOpenPalette}
          className="field flex h-[24px] w-56 shrink-0 items-center gap-1.5 px-2 text-xs text-fg-faint hover:border-fg-faint"
        >
          <Search size={12} strokeWidth={1.75} />
          <span>Run a command</span>
          <span className="ml-auto flex gap-0.5">
            <Kbd>Ctrl</Kbd>
            <Kbd>K</Kbd>
          </span>
        </button>
      </div>
    </header>
  );
}

function Group({ children }: { children: ReactNode }) {
  return <div className="flex items-center gap-0.5 border-l border-line pl-1.5 first-of-type:border-l-0">{children}</div>;
}

interface BarButtonProps {
  icon: LucideIcon;
  label: string;
  onClick: () => void;
  disabled?: boolean;
  pressed?: boolean;
  tone?: "warn" | undefined;
  title?: string;
  iconClass?: string;
}

function BarButton({ icon: Icon, label, onClick, disabled = false, pressed, tone, title, iconClass = "" }: BarButtonProps) {
  const surface =
    tone === "warn"
      ? "border-warn/70 bg-warn/15 text-fg-bright"
      : pressed === true
        ? "border-line-strong bg-active text-fg-bright"
        : "border-transparent text-fg hover:bg-active";
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      aria-pressed={pressed}
      title={title ?? label}
      className={`flex h-[28px] items-center gap-1.5 rounded-xs border px-2 text-xs disabled:cursor-not-allowed disabled:opacity-45 disabled:hover:bg-transparent ${surface}`}
    >
      <Icon size={14} strokeWidth={1.75} className={tone === "warn" ? "text-warn" : disabled ? "" : iconClass} />
      {label}
    </button>
  );
}

function ExportMenu({
  busy,
  onExport,
  onCopy,
}: {
  busy: boolean;
  onExport: (format: "markdown" | "json") => void;
  onCopy: () => void;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent | KeyboardEvent) => {
      if (e instanceof KeyboardEvent ? e.key === "Escape" : !ref.current?.contains(e.target as Node)) setOpen(false);
    };
    window.addEventListener("mousedown", close);
    window.addEventListener("keydown", close);
    return () => {
      window.removeEventListener("mousedown", close);
      window.removeEventListener("keydown", close);
    };
  }, [open]);

  const item = (icon: LucideIcon, label: string, hint: string, run: () => void, disabled = false) => {
    const Icon = icon;
    return (
      <button
        type="button"
        role="menuitem"
        disabled={disabled}
        onClick={() => {
          setOpen(false);
          run();
        }}
        className="flex h-[26px] w-full items-center gap-2 px-2.5 text-left text-xs text-fg hover:bg-select hover:text-select-fg disabled:text-fg-faint disabled:hover:bg-transparent"
      >
        <Icon size={13} strokeWidth={1.75} />
        <span>{label}</span>
        <span className="num ml-auto pl-4 text-2xs opacity-70">{hint}</span>
      </button>
    );
  };

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
        className={`flex h-[28px] items-center gap-1.5 rounded-xs border px-2 text-xs ${
          open ? "border-line-strong bg-active text-fg-bright" : "border-transparent text-fg hover:bg-active"
        }`}
      >
        <FileDown size={14} strokeWidth={1.75} />
        Export report
        <ChevronDown size={12} strokeWidth={1.75} className="text-fg-faint" />
      </button>
      {open && (
        <div role="menu" className="absolute top-[30px] right-0 z-50 w-64 rounded-xs border border-line-strong bg-panel py-1 shadow-menu">
          {item(FileDown, "Save as Markdown", ".md", () => onExport("markdown"), busy)}
          {item(FileDown, "Save as JSON", ".json", () => onExport("json"), busy)}
          <div className="my-1 h-px bg-line" />
          {item(ClipboardCopy, "Copy Markdown to clipboard", "", onCopy)}
        </div>
      )}
    </div>
  );
}

/** Same geometry as src-tauri/icons/app-icon.svg without the tile; the break is the injected fault. */
function Logo() {
  return (
    <svg width="16" height="16" viewBox="280 272 464 480" aria-hidden className="text-fg-bright">
      <path fill="currentColor" d="M296 288H728V368L603.56 480H491.56L616 368H296Z" />
      <path fill="currentColor" d="M420.44 544H532.44L408 656H728V736H296V656Z" />
    </svg>
  );
}
