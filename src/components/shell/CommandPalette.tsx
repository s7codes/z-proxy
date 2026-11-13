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
      overlayClassName="fixed inset-0 z-40 bg-bg/70"
      contentClassName="fixed left-1/2 top-[14%] z-50 w-[540px] -translate-x-1/2 border border-line-strong bg-panel"
    >
      <Command.Input
        placeholder="Type a command"
        className="h-9 w-full border-b border-line bg-transparent px-3 text-base text-fg-bright outline-none placeholder:text-fg-faint"
      />
      <Command.List className="max-h-[320px] overflow-y-auto py-1">
        <Command.Empty className="px-3 py-2 text-xs text-fg-faint">No matching command.</Command.Empty>
        {groups.map((group) => (
          <Command.Group
            key={group}
            heading={group}
            className="[&_[cmdk-group-heading]]:label-caps [&_[cmdk-group-heading]]:px-3 [&_[cmdk-group-heading]]:py-1 [&_[cmdk-group-heading]]:text-fg-faint"
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
                  className="flex h-7 cursor-default items-center gap-2 px-3 text-sm text-fg data-[selected=true]:bg-active data-[selected=true]:text-fg-bright"
                >
                  <c.icon size={13} strokeWidth={1.5} className="text-fg-dim" />
                  <span>{c.label}</span>
                  {c.shortcut !== undefined && (
                    <span className="num ml-auto text-2xs text-fg-faint">{c.shortcut}</span>
                  )}
                </Command.Item>
              ))}
          </Command.Group>
        ))}
      </Command.List>
    </Command.Dialog>
  );
}
