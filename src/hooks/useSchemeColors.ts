import { useEffect, useState } from "react";
import type { Tone } from "../lib/tone";

export interface SchemeColors {
  tone: Record<Tone, string>;
  surface: string;
  grid: string;
  dark: boolean;
}

const QUERY = "(prefers-color-scheme: dark)";

function read(): SchemeColors {
  const style = getComputedStyle(document.documentElement);
  const get = (name: string) => style.getPropertyValue(name).trim();
  return {
    tone: { ok: get("--status-ok"), warn: get("--status-warn"), fault: get("--status-fault"), muted: get("--status-muted") },
    surface: get("--surface-content"),
    grid: get("--hairline"),
    dark: window.matchMedia(QUERY).matches,
  };
}

/**
 * Resolved palette values for consumers that cannot take a CSS variable: React Flow derives
 * SVG marker ids from the marker color string, so it needs a literal per scheme.
 */
export function useSchemeColors(): SchemeColors {
  const [colors, setColors] = useState(read);
  useEffect(() => {
    const media = window.matchMedia(QUERY);
    const update = () => setColors(read());
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);
  return colors;
}
