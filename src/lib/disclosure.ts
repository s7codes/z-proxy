import type { DisclosureKind } from "./types";

export const DISCLOSURE_LABEL: Record<DisclosureKind, string> = {
  nodeStackTrace: "Node.js stack trace",
  pythonTraceback: "Python traceback",
  rustPanic: "Rust panic",
  goPanic: "Go panic",
  jvmStackTrace: "JVM stack trace",
  dotNetStackTrace: ".NET stack trace",
  sqlError: "SQL error",
  sensitiveFieldLeak: "Sensitive field",
};
