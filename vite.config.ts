import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Vendor code in its own chunks keeps every chunk under Vite's default 500 kB warning, so a
// dependency that grows shows up in the build output instead of disappearing into one
// bundle. Higher priority claims a module first; the catch-all takes the remaining packages.
const VENDOR_CHUNKS = [
  { name: "react", test: /node_modules[\\/](?:react|react-dom|scheduler)[\\/]/, priority: 30 },
  { name: "flow", test: /node_modules[\\/](?:@xyflow|d3-[\w-]+|zustand|classcat)[\\/]/, priority: 20 },
  { name: "vendor", test: /node_modules[\\/]/, priority: 10 },
];

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
    // Vite 8 bundles with Rolldown: `rolldownOptions.output.codeSplitting` replaces the
    // deprecated `rollupOptions.output.manualChunks`.
    rolldownOptions: {
      output: {
        codeSplitting: { groups: VENDOR_CHUNKS },
      },
    },
  },
});
