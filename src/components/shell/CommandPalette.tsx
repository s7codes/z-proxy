import { Command } from "cmdk";
import type { LucideIcon } from "lucide-react";

export interface PaletteCommand {
  id: string;
  label: string;
  group: string;
  icon: LucideIcon;
  shortcut?: string;
  run: () => void;
}

interface CommandPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  commands: readonly PaletteCommand[];
}

export function CommandPalette({ open, onOpenChange, commands }: CommandPaletteProps) {
  const groups = [...new Set(commands.map((c) => c.group))];

  return (
    <Command.Dialog
      open={open}
      onOpenChange={onOpenChange}
      label="Command palette"
      loop
      overlayClassName="fixed inset-0 z-40 bg-black/25"
      contentClassName="fixed left-1/2 top-[12%] z-50 w-[560px] -translate-x-1/2 overflow-hidden rounded-xs border border-line-strong bg-panel shadow-menu"
    >
      <Command.Input
        placeholder="Type a command"
        className="h-9 w-full border-b border-line bg-field px-3 text-base text-fg-bright outline-none placeholder:text-fg-faint"
      />
      <Command.List className="max-h-[320px] overflow-y-auto py-1">
        <Command.Empty className="px-3 py-2 text-xs text-fg-faint">No matching command.</Command.Empty>
        {groups.map((group) => (
          <Command.Group
            key={group}
            heading={group}
            className="[&_[cmdk-group-heading]]:px-3 [&_[cmdk-group-heading]]:pt-1.5 [&_[cmdk-group-heading]]:pb-0.5 [&_[cmdk-group-heading]]:text-2xs [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:text-fg-dim"
          >
            {commands
              .filter((c) => c.group === group)
              .map((c) => (
                <Command.Item
                  key={c.id}
                  value={`${c.group} ${c.label}`}
                  onSelect={() => {
                    c.run();
                    onOpenChange(false);
                  }}
                  className="group flex h-[26px] cursor-default items-center gap-2 px-3 text-sm text-fg data-[selected=true]:bg-select data-[selected=true]:text-select-fg"
                >
                  <c.icon size={14} strokeWidth={1.75} className="text-fg-dim group-data-[selected=true]:text-select-fg" />
                  <span>{c.label}</span>
                  {c.shortcut !== undefined && (
                    <span className="num ml-auto text-2xs text-fg-faint group-data-[selected=true]:text-select-fg">{c.shortcut}</span>
                  )}
                </Command.Item>
              ))}
          </Command.Group>
        ))}
      </Command.List>
    </Command.Dialog>
  );
}
