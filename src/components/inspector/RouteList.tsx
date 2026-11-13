import { FolderSearch } from "lucide-react";

export function RouteList() {
  return (
    <div className="flex items-start gap-2 rounded-xs border border-dashed border-line px-2 py-2 text-xs text-fg-faint">
      <FolderSearch size={13} strokeWidth={1.5} className="mt-0.5 shrink-0" />
      <div className="flex flex-col gap-0.5">
        <span className="text-fg-dim">Route scanner not attached</span>
        <span>Next.js, Express, Fastify, Go and OpenAPI sources are indexed once a project root is mounted.</span>
      </div>
    </div>
  );
}
