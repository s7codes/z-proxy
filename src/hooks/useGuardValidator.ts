import { useEffect, useRef, useState } from "react";
import { isTransportError, validateTarget } from "../lib/ipc";
import type { EngineError, ValidatedTarget } from "../lib/types";

const DEBOUNCE_MS = 200;

export type GuardState =
  | { phase: "empty" }
  | { phase: "pending"; input: string }
  | { phase: "accepted"; input: string; target: ValidatedTarget }
  | { phase: "rejected"; input: string; error: EngineError }
  /** The engine could not be asked. Distinct from a rejection: no guard decision exists. */
  | { phase: "offline"; input: string; reason: string };

export function useGuardValidator(input: string): GuardState {
  const [state, setState] = useState<GuardState>({ phase: "empty" });
  // Probes have up to 750 ms of latency, so responses can arrive out of order relative to
  // keystrokes. Only the most recent request may write state.
  const generation = useRef(0);

  useEffect(() => {
    const trimmed = input.trim();
    const current = ++generation.current;

    if (trimmed === "") {
      setState({ phase: "empty" });
      return;
    }

    setState({ phase: "pending", input: trimmed });
    const timer = window.setTimeout(() => {
      void validateTarget(trimmed).then((result) => {
        if (current !== generation.current) return;
        if (result.ok) {
          setState({ phase: "accepted", input: trimmed, target: result.value });
          return;
        }
        const { error } = result;
        if (isTransportError(error)) {
          setState({ phase: "offline", input: trimmed, reason: error.message });
        } else {
          setState({ phase: "rejected", input: trimmed, error });
        }
      });
    }, DEBOUNCE_MS);

    return () => window.clearTimeout(timer);
  }, [input]);

  return state;
}
