import { memo, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { FolderOpen, FolderTree, LoaderCircle, RefreshCw, Search } from "lucide-react";
import type { RouteScanControl } from "../../hooks/useRouteScan";
import { formatLatency } from "../../lib/format";
import { fileLabel, SOURCE_LABEL } from "../../lib/routes";
import type { DiscoveredRoute, RouteMethod, RouteScanReport, RouteSource } from "../../lib/types";
import { ErrorLine } from "../chaos/ErrorLine";

const ROW_HEIGHT = 34;
const MAX_LISTED_ISSUES = 20;

// Same abbreviations HTTP clients use, so every badge fits one fixed column.
const METHOD_BADGE: Record<RouteMethod, string> = {
  GET: "GET",
  POST: "POST",
  PUT: "PUT",
  PATCH: "PATCH",
  DELETE: "DEL",
  HEAD: "HEAD",
  OPTIONS: "OPT",
  ANY: "ANY",
};

interface RouteListProps {
  scan: RouteScanControl;
  selected: DiscoveredRoute | null;
  onSelect: (route: DiscoveredRoute) => void;
  online: boolean;
}

export function routeKey(route: DiscoveredRoute): string {
  return `${route.method} ${route.path} ${route.file}:${route.line}`;
}

export function RouteList({ scan, selected, onSelect, online }: RouteListProps) {
  const [filter, setFilter] = useState("");
  const scrollRef = useRef<HTMLDivElement>(null);
  const { report } = scan;

  const routes = useMemo(() => {
    const all = report?.routes ?? [];
    const needle = filter.trim().toLowerCase();
    if (needle === "") return all;
    return all.filter((route) => `${route.method} ${route.path} ${route.file}`.toLowerCase().includes(needle));
  }, [report, filter]);

  const virtualizer = useVirtualizer({
    count: routes.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 12,
  });

  const selectedKey = selected === null ? null : routeKey(selected);

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    if (routes.length === 0) return;
    const current = routes.findIndex((route) => routeKey(route) === selectedKey);
    const next =
      current === -1
        ? 0
        : Math.min(routes.length - 1, Math.max(0, current + (e.key === "ArrowDown" ? 1 : -1)));
    const route = routes[next];
    if (route === undefined) return;
    onSelect(route);
    virtualizer.scrollToIndex(next, { align: "auto" });
  };

  const canScan = online && !scan.scanning && scan.root.trim() !== "";

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex shrink-0 items-center gap-1 px-2.5 pb-1.5">
        <label className="flex h-6 min-w-0 flex-1 items-center gap-1.5 rounded-xs border border-line bg-bg px-1.5 focus-within:border-fg-faint">
          <FolderTree size={12} strokeWidth={1.5} className="shrink-0 text-fg-faint" />
          <input
            value={scan.root}
            onChange={(e) => scan.setRoot(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && canScan) scan.scan();
            }}
            spellCheck={false}
            autoComplete="off"
            placeholder="project root"
            aria-label="Project root"
            title={scan.root}
            className="num min-w-0 flex-1 bg-transparent text-xs text-fg-bright outline-none placeholder:text-fg-faint"
          />
        </label>
        <IconButton label="Browse for project root" disabled={!online || scan.scanning} onClick={scan.browse}>
          <FolderOpen size={12} strokeWidth={1.5} />
        </IconButton>
        <IconButton label="Scan routes" disabled={!canScan} onClick={() => scan.scan()}>
          {scan.scanning ? (
            <LoaderCircle size={12} strokeWidth={1.5} className="animate-spin" />
          ) : (
            <RefreshCw size={12} strokeWidth={1.5} />
          )}
        </IconButton>
      </div>

      {scan.error !== null && <ErrorLine error={scan.error} />}
      {report !== null && <ScanSummary report={report} />}

      {report !== null && report.routes.length > 0 && (
        <label className="mx-2.5 mb-1 flex h-5 shrink-0 items-center gap-1.5 rounded-xs border border-line bg-bg px-1.5 focus-within:border-fg-faint">
          <Search size={11} strokeWidth={1.5} className="shrink-0 text-fg-faint" />
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            spellCheck={false}
            placeholder="filter method, path, file"
            aria-label="Filter routes"
            className="num min-w-0 flex-1 bg-transparent text-2xs text-fg-bright outline-none placeholder:text-fg-faint"
          />
          {filter !== "" && <span className="num shrink-0 text-2xs text-fg-faint">{routes.length}</span>}
        </label>
      )}

      <div
        ref={scrollRef}
        tabIndex={0}
        role="listbox"
        aria-label="Discovered routes"
        onKeyDown={onKeyDown}
        className="relative min-h-0 flex-1 overflow-y-auto border-t border-line outline-none focus-visible:border-fg-faint"
      >
        {routes.length === 0 ? (
          <EmptyState report={report} filtered={filter.trim() !== ""} online={online} />
        ) : (
          <div style={{ height: virtualizer.getTotalSize() }} className="relative w-full">
            {virtualizer.getVirtualItems().map((item) => {
              const route = routes[item.index];
              if (route === undefined) return null;
              const key = routeKey(route);
              return (
                <RouteRow key={key} route={route} top={item.start} selected={key === selectedKey} onSelect={onSelect} />
              );
            })}
          </div>
        )}
      </div>

      {report !== null && report.issues.length > 0 && <Issues report={report} />}
    </div>
  );
}

const RouteRow = memo(function RouteRow({
  route,
  top,
  selected,
  onSelect,
}: {
  route: DiscoveredRoute;
  top: number;
  selected: boolean;
  onSelect: (route: DiscoveredRoute) => void;
}) {
  return (
    <div
      role="option"
      aria-selected={selected}
      onClick={() => onSelect(route)}
      className={`absolute left-0 flex w-full flex-col justify-center gap-px border-b border-l border-b-line/50 px-2.5 ${
        selected ? "border-l-fg-dim bg-active" : "border-l-transparent hover:bg-active"
      }`}
      style={{ height: ROW_HEIGHT, transform: `translateY(${top}px)` }}
    >
      <div className="flex min-w-0 items-center gap-1.5">
        <span className="num w-9 shrink-0 border border-line text-center text-2xs leading-[14px] text-fg-dim">
          {METHOD_BADGE[route.method]}
        </span>
        <PathText path={route.path} />
      </div>
      <div className="num flex min-w-0 items-center gap-2 pl-[42px] text-2xs text-fg-faint">
        <span className="truncate" title={`${route.file}:${route.line}`}>
          {fileLabel(route.file, route.line)}
        </span>
        <span className="ml-auto shrink-0">{SOURCE_LABEL[route.source]}</span>
      </div>
    </div>
  );
});

function PathText({ path }: { path: string }) {
  const parts: ReactNode[] = [];
  let last = 0;
  for (const match of path.matchAll(/\{[^{}]+\}/g)) {
    const at = match.index;
    if (at > last) parts.push(path.slice(last, at));
    parts.push(
      <span key={at} className="text-fg-dim">
        {match[0]}
      </span>,
    );
    last = at + match[0].length;
  }
  if (last < path.length) parts.push(path.slice(last));
  return (
    <span className="num truncate text-xs text-fg-bright" title={path}>
      {parts}
    </span>
  );
}

function ScanSummary({ report }: { report: RouteScanReport }) {
  const bySource = new Map<RouteSource, number>();
  for (const route of report.routes) bySource.set(route.source, (bySource.get(route.source) ?? 0) + 1);
  const breakdown = Array.from(bySource, ([source, count]) => `${SOURCE_LABEL[source]} ${count}`).join("  ");

  return (
    <div className="num flex shrink-0 flex-col gap-px px-2.5 pb-1.5 text-2xs">
      <div className="flex items-center gap-2 text-fg-faint">
        <span>
          <span className="text-fg">{report.routes.length}</span> routes
        </span>
        <span>
          <span className="text-fg-dim">{report.filesParsed}</span>/{report.filesVisited} files
        </span>
        <span>{formatLatency(report.elapsedUs)}</span>
        {report.truncated && (
          <span className="ml-auto text-warn" title="File or route cap reached; results are partial">
            truncated
          </span>
        )}
      </div>
      {breakdown !== "" && (
        <div className="truncate text-fg-faint" title={breakdown}>
          {breakdown}
        </div>
      )}
    </div>
  );
}

function Issues({ report }: { report: RouteScanReport }) {
  return (
    <details className="max-h-28 shrink-0 overflow-y-auto border-t border-line px-2.5 py-1 text-2xs">
      <summary className="cursor-default text-fg-faint marker:text-fg-faint">
        {report.issues.length} file{report.issues.length === 1 ? "" : "s"} skipped
      </summary>
      <ul className="num flex flex-col pt-1">
        {report.issues.slice(0, MAX_LISTED_ISSUES).map((issue) => (
          <li key={`${issue.file}:${issue.reason}`} className="truncate text-fg-faint" title={`${issue.file}: ${issue.reason}`}>
            <span className="text-fg-dim">{issue.file}</span> {issue.reason}
          </li>
        ))}
      </ul>
    </details>
  );
}

function EmptyState({ report, filtered, online }: { report: RouteScanReport | null; filtered: boolean; online: boolean }) {
  const message = filtered
    ? "No routes match the filter."
    : report !== null
      ? `No route declarations in ${report.filesParsed} source files.`
      : online
        ? "Index Next.js, Express, Fastify, Hono, Axum, Go and OpenAPI routes from a local project root."
        : "Route scanning runs in the desktop engine; launch through `npm run tauri dev`.";
  return <div className="px-2.5 py-2 text-xs text-fg-faint">{message}</div>;
}

function IconButton({
  label,
  disabled,
  onClick,
  children,
}: {
  label: string;
  disabled: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      title={label}
      aria-label={label}
      disabled={disabled}
      onClick={onClick}
      className="flex size-6 shrink-0 items-center justify-center rounded-xs border border-line text-fg-dim hover:border-line-strong hover:bg-active hover:text-fg disabled:cursor-not-allowed disabled:opacity-40"
    >
      {children}
    </button>
  );
}
