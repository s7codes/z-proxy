import { useState, type ReactNode } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";

interface PanelHeaderProps {
  title: string;
  meta?: ReactNode;
  children?: ReactNode;
}

export function PanelHeader({ title, meta, children }: PanelHeaderProps) {
  return (
    <div className="flex h-[26px] shrink-0 items-center gap-2 border-b border-line bg-panel px-2.5">
      <span className="text-sm font-semibold text-fg-bright">{title}</span>
      {meta !== undefined && <span className="num text-2xs text-fg-faint">{meta}</span>}
      <div className="ml-auto flex items-center gap-1">{children}</div>
    </div>
  );
}

interface SectionProps {
  title: string;
  aside?: ReactNode;
  defaultOpen?: boolean;
  children: ReactNode;
}

/** Disclosure group in the style of an inspector pane; collapsed state is per mount. */
export function Section({ title, aside, defaultOpen = true, children }: SectionProps) {
  const [open, setOpen] = useState(defaultOpen);
  const Chevron = open ? ChevronDown : ChevronRight;
  return (
    <section className="border-b border-line">
      <div className="flex h-6 items-center gap-1 pr-2.5 pl-1">
        <button
          type="button"
          aria-expanded={open}
          onClick={() => setOpen(!open)}
          className="flex h-full min-w-0 flex-1 items-center gap-1 text-left text-fg hover:text-fg-bright"
        >
          <Chevron size={12} strokeWidth={2} className="shrink-0 text-fg-faint" />
          <span className="caption truncate">{title}</span>
        </button>
        {aside !== undefined && <span className="flex shrink-0 items-center">{aside}</span>}
      </div>
      {open && <div className="px-2.5 pb-2.5">{children}</div>}
    </section>
  );
}

/** Round state lamp; the hue carries the state, the size never changes. */
export function StatusDot({ className }: { className: string }) {
  return <span aria-hidden className={`inline-block size-[7px] shrink-0 rounded-full ${className}`} />;
}

interface ToolButtonProps {
  label: string;
  onClick: () => void;
  active?: boolean;
  disabled?: boolean;
  title?: string;
  children?: ReactNode;
}

/** Flat command-bar button: no chrome until hovered, a sunken surface while pressed. */
export function ToolButton({ label, onClick, active = false, disabled = false, title, children }: ToolButtonProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={title ?? label}
      aria-pressed={active}
      className={`flex h-[22px] items-center gap-1 rounded-xs border px-1.5 text-xs disabled:cursor-not-allowed disabled:opacity-40 ${
        active
          ? "border-line-strong bg-active text-fg-bright"
          : "border-transparent text-fg-dim hover:bg-active hover:text-fg"
      }`}
    >
      {children}
      <span>{label}</span>
    </button>
  );
}

export function Kbd({ children }: { children: ReactNode }) {
  return (
    <kbd className="num rounded-xs border border-b-2 border-line-strong bg-control px-1 text-2xs leading-[13px] text-fg-dim">
      {children}
    </kbd>
  );
}

export interface TabDef<T extends string> {
  id: T;
  label: string;
  badge?: ReactNode;
}

interface TabStripProps<T extends string> {
  tabs: ReadonlyArray<TabDef<T>>;
  value: T;
  onChange: (id: T) => void;
  label: string;
  children?: ReactNode;
}

/**
 * Notebook tabs: the active tab shares the content surface and opens into it, inactive tabs
 * sit on the chrome. Arrow keys move between tabs as in a native tab control.
 */
export function TabStrip<T extends string>({ tabs, value, onChange, label, children }: TabStripProps<T>) {
  const move = (delta: number) => {
    const index = tabs.findIndex((tab) => tab.id === value);
    const next = tabs[(index + delta + tabs.length) % tabs.length];
    if (next !== undefined) onChange(next.id);
  };
  return (
    <div className="relative flex h-[28px] shrink-0 items-end gap-px bg-panel px-1.5">
      <div className="absolute inset-x-0 bottom-0 h-px bg-line" aria-hidden />
      <div
        role="tablist"
        aria-label={label}
        className="flex items-end gap-px"
        onKeyDown={(e) => {
          if (e.key === "ArrowRight") move(1);
          else if (e.key === "ArrowLeft") move(-1);
        }}
      >
        {tabs.map((tab) => {
          const active = tab.id === value;
          return (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={active}
              tabIndex={active ? 0 : -1}
              onClick={() => onChange(tab.id)}
              className={`relative flex h-[24px] items-center gap-1.5 rounded-t-xs border border-b-0 px-2.5 text-xs ${
                active
                  ? "z-10 border-line bg-bg text-fg-bright"
                  : "border-transparent text-fg-dim hover:bg-active hover:text-fg"
              }`}
            >
              {tab.label}
              {tab.badge}
              {active && <span className="absolute inset-x-0 -bottom-px h-px bg-bg" aria-hidden />}
            </button>
          );
        })}
      </div>
      <div className="relative ml-auto flex h-full items-center gap-1 pb-px">{children}</div>
    </div>
  );
}
