import type { ReactNode } from "react";

interface PanelHeaderProps {
  title: string;
  meta?: ReactNode;
  children?: ReactNode;
}

export function PanelHeader({ title, meta, children }: PanelHeaderProps) {
  return (
    <div className="flex h-7 shrink-0 items-center gap-2 border-b border-line bg-panel px-2.5">
      <span className="label-caps text-fg-dim">{title}</span>
      {meta !== undefined && <span className="num text-2xs text-fg-faint">{meta}</span>}
      <div className="ml-auto flex items-center gap-1">{children}</div>
    </div>
  );
}

interface SectionProps {
  title: string;
  aside?: ReactNode;
  children: ReactNode;
}

export function Section({ title, aside, children }: SectionProps) {
  return (
    <section className="border-b border-line">
      <div className="flex h-6 items-center px-2.5">
        <span className="label-caps text-fg-faint">{title}</span>
        {aside !== undefined && <span className="ml-auto">{aside}</span>}
      </div>
      <div className="px-2.5 pb-2.5">{children}</div>
    </section>
  );
}

export function StatusSquare({ className }: { className: string }) {
  return <span aria-hidden className={`inline-block size-1.5 shrink-0 ${className}`} />;
}

interface ToolButtonProps {
  label: string;
  onClick: () => void;
  active?: boolean;
  disabled?: boolean;
  title?: string;
  children?: ReactNode;
}

export function ToolButton({ label, onClick, active = false, disabled = false, title, children }: ToolButtonProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={title ?? label}
      aria-pressed={active}
      className={`flex h-5 items-center gap-1 rounded-xs border px-1.5 text-xs transition-colors duration-75 disabled:cursor-not-allowed disabled:opacity-40 ${
        active
          ? "border-line-strong bg-active text-fg-bright"
          : "border-transparent text-fg-dim hover:border-line hover:bg-active hover:text-fg"
      }`}
    >
      {children}
      <span>{label}</span>
    </button>
  );
}

export function Kbd({ children }: { children: ReactNode }) {
  return (
    <kbd className="num rounded-xs border border-line bg-bg px-1 text-2xs text-fg-dim">{children}</kbd>
  );
}
