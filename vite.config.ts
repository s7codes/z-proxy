import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // The Tauri CLI owns the terminal during `tauri dev`; clearing it would hide Rust build errors.
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: "127.0.0.1",
    watch: {
      ignored: ["**/src-tauri/**"],
    },
  },
  build: {
    target: "es2022",
    sourcemap: false,
    // Bundle is loaded from disk by the webview, not over a network; split points buy nothing.
    chunkSizeWarningLimit: 1024,
  },
});
