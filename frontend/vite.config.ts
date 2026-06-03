import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";

const rawPort = process.env.PORT ?? "3000";
const port = Number(rawPort);

if (Number.isNaN(port) || port <= 0) {
  throw new Error(`Invalid PORT value: "${rawPort}"`);
}

const basePath = process.env.BASE_PATH ?? "/";

export default defineConfig({
  base: basePath,
  plugins: [
    react(),
    tailwindcss(),
  ],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "src"),
    },
    dedupe: ["react", "react-dom"],
  },
  root: path.resolve(import.meta.dirname),
  build: {
    outDir: path.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true,
    sourcemap: process.env.NODE_ENV !== "production",
    // Chunk size warning threshold — helps catch bloated bundles early
    chunkSizeWarningLimit: 1000,
    rollupOptions: {
      onwarn(warning, warn) {
        // shadcn/radix-ui components ship with "use client" directives (a Next.js RSC
        // marker). Rollup doesn't understand it, emits a MODULE_LEVEL_DIRECTIVE warning,
        // then fails to resolve the sourcemap position — producing the SOURCEMAP_ERROR
        // noise. Both are harmless in a pure client-side Vite build.
        if (
          warning.code === "MODULE_LEVEL_DIRECTIVE" &&
          warning.message.includes('"use client"')
        ) return;
        if (warning.code === "SOURCEMAP_ERROR") return;
        warn(warning);
      },
      output: {
        // Split vendor code into separate chunk for better caching
        manualChunks(id) {
          if (id.includes("node_modules")) {
            if (id.includes("react") || id.includes("wouter")) return "react-vendor";
            if (id.includes("@tanstack")) return "query-vendor";
            if (id.includes("lucide")) return "icons-vendor";
            if (id.includes("recharts") || id.includes("d3")) return "chart-vendor";
            return "vendor";
          }
        },
      },
    },
  },
  server: {
    port,
    strictPort: true,
    host: "0.0.0.0",
    allowedHosts: true,
    fs: {
      strict: true,
    },
    proxy: {
      "/api": {
        target: process.env.API_URL ?? "http://localhost:5000",
        changeOrigin: true,
        secure: false,
        // Keep SSE connections alive — without this, Vite's proxy closes long-lived
        // HTTP streams (EventSource) after a short idle timeout, causing 404/ERR_INCOMPLETE_CHUNKED_ENCODING
        configure: (proxy) => {
          proxy.on("proxyReq", (_proxyReq, req) => {
            // Mark SSE requests so the proxy doesn't buffer them
            if (req.headers["accept"] === "text/event-stream") {
              _proxyReq.setHeader("X-Accel-Buffering", "no");
            }
          });
        },
      },
      "/stream": {
        target: process.env.API_URL ?? "http://localhost:5000",
        changeOrigin: true,
        secure: false,
        ws: true,
      },
    },
  },
  preview: {
    port,
    host: "0.0.0.0",
    allowedHosts: true,
  },
});
