import type { GuardState } from "../hooks/useGuardValidator";

export type Tone = "ok" | "warn" | "fault" | "muted";

export const TONE_TEXT: Record<Tone, string> = {
  ok: "text-ok",
  warn: "text-warn",
  fault: "text-fault",
  muted: "text-muted",
};

export const TONE_BG: Record<Tone, string> = {
  ok: "bg-ok",
  warn: "bg-warn",
  fault: "bg-fault",
  muted: "bg-muted",
};

export function httpStatusTone(status: number | null): Tone {
  if (status === null) return "fault";
  if (status >= 500) return "fault";
  if (status >= 300) return "warn";
  return "ok";
}

export function guardTone(state: GuardState): Tone {
  switch (state.phase) {
    case "empty":
    case "pending":
    case "offline":
      return "muted";
    case "rejected":
      return "fault";
    case "accepted":
      return state.target.probe.state === "reachable"
        ? httpStatusTone(state.target.probe.status)
        : "warn";
  }
}
