import { defineConfig } from "vitest/config";
import path from "node:path";

// Vitest config for the xct-claws web UI. Mirrors the `@/*` path alias
// declared in tsconfig.json so tests can import from "@/lib/..." the same
// way the app does. jsdom is the environment so future React component
// tests can render into a real DOM; the `cn()` smoke test we ship today
// doesn't need it, but it costs nothing to have it ready.
export default defineConfig({
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
    exclude: ["node_modules", ".next", "out", "**/*.test-d.*"],
    globals: false,
  },
});
