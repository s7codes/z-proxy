import { useCallback, useEffect, useRef, useState } from "react";
import { auditFileName, buildAuditReport, renderAuditReport, type AuditInputs } from "../lib/export";
import { formatBytes } from "../lib/format";
import { saveAuditReport } from "../lib/ipc";
import type { Tone } from "../lib/tone";
import type { ReportFormat } from "../lib/types";

const NOTICE_MS = 6_000;

export interface ExportNotice {
  tone: Tone;
  text: string;
}

export interface AuditExportControl {
  busy: boolean;
  notice: ExportNotice | null;
  /** Native save dialog, then the engine writes the file. */
  save: (format: ReportFormat) => void;
  /** Markdown rendering to the clipboard. */
  copy: () => void;
}

/** `document.execCommand` path for webviews that refuse the async clipboard API. */
function legacyCopy(text: string): boolean {
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.appendChild(area);
  area.select();
  try {
    return document.execCommand("copy");
  } catch {
    return false;
  } finally {
    area.remove();
  }
}

export function useAuditExport(inputs: Omit<AuditInputs, "generatedAt">): AuditExportControl {
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<ExportNotice | null>(null);
  // The report is rendered at the moment of the action, from the latest session state,
  // without rebuilding callbacks (and the palette command list) on every telemetry event.
  const latest = useRef(inputs);
  latest.current = inputs;

  useEffect(() => {
    if (notice === null) return;
    const timer = window.setTimeout(() => setNotice(null), NOTICE_MS);
    return () => window.clearTimeout(timer);
  }, [notice]);

  const render = useCallback((format: ReportFormat) => {
    const generatedAt = new Date();
    const report = buildAuditReport({ ...latest.current, generatedAt });
    return { generatedAt, contents: renderAuditReport(report, format) };
  }, []);

  const save = useCallback(
    (format: ReportFormat) => {
      const { generatedAt, contents } = render(format);
      setBusy(true);
      void saveAuditReport(format, auditFileName(generatedAt, format), contents).then((result) => {
        setBusy(false);
        if (!result.ok) {
          setNotice({ tone: "fault", text: `${result.error.code} ${result.error.message}` });
        } else if (result.value === null) {
          setNotice({ tone: "muted", text: "Export cancelled" });
        } else {
          setNotice({ tone: "ok", text: `Saved ${result.value}` });
        }
      });
    },
    [render],
  );

  const copy = useCallback(() => {
    const { contents } = render("markdown");
    const size = formatBytes(new Blob([contents]).size);
    const done = () => setNotice({ tone: "ok", text: `Markdown report copied (${size})` });
    const failed = () => setNotice({ tone: "fault", text: "Clipboard unavailable; export to a file instead" });
    if (navigator.clipboard === undefined) {
      if (legacyCopy(contents)) done();
      else failed();
      return;
    }
    navigator.clipboard.writeText(contents).then(done, () => {
      if (legacyCopy(contents)) done();
      else failed();
    });
  }, [render]);

  return { busy, notice, save, copy };
}
