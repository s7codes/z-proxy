import type { TransportError } from "../../lib/ipc";
import type { EngineError } from "../../lib/types";

export function ErrorLine({ error }: { error: EngineError | TransportError }) {
  return (
    <div className="flex min-h-6 shrink-0 items-start gap-1.5 border-b border-line bg-fault/5 px-2.5 py-1 text-2xs">
      <span className="num shrink-0 text-fault">{error.code}</span>
      <span className="text-fg-dim">{error.message}</span>
    </div>
  );
}
