import react from "@vitejs/plugin-react";
import type { Connect, Plugin } from "vite";
import { defineConfig } from "vite";
import { normalizeAppName } from "./app/product.ts";

function runtimeConfigScript(appName: string) {
  const serialized = JSON.stringify({ appName })
    .replaceAll("<", "\\u003c")
    .replaceAll("\u2028", "\\u2028")
    .replaceAll("\u2029", "\\u2029");
  return `Object.defineProperty(globalThis,"__ALERT_HUB_CONFIG__",{value:Object.freeze(${serialized}),writable:false,configurable:false});\n`;
}

function runtimeManifest(appName: string) {
  return {
    id: "/",
    name: appName,
    short_name: appName.slice(0, 24),
    description: "Distributed incident operations and resilient alert delivery.",
    start_url: "/",
    scope: "/",
    display: "standalone",
    display_override: ["window-controls-overlay", "standalone", "minimal-ui"],
    orientation: "any",
    background_color: "#07100e",
    theme_color: "#07100e",
    categories: ["productivity", "utilities"],
    icons: [
      { src: "/icon-192.png", sizes: "192x192", type: "image/png", purpose: "any" },
      { src: "/icon-512.png", sizes: "512x512", type: "image/png", purpose: "maskable" },
    ],
    shortcuts: [
      {
        name: "Active incidents",
        short_name: "Incidents",
        description: "Open the active incident ledger",
        url: "/incidents",
      },
      {
        name: "Cluster health",
        short_name: "Cluster",
        description: "Inspect peer synchronization",
        url: "/cluster",
      },
    ],
  };
}

function runtimeMiddleware(): Connect.NextHandleFunction {
  const appName = normalizeAppName(process.env.APP_NAME);
  const config = runtimeConfigScript(appName);
  const manifest = `${JSON.stringify(runtimeManifest(appName))}\n`;
  return (request, response, next) => {
    const pathname = request.url?.split("?", 1)[0];
    if (pathname === "/runtime-config.js") {
      response.statusCode = 200;
      response.setHeader("Content-Type", "application/javascript; charset=utf-8");
      response.setHeader("Cache-Control", "no-store");
      response.setHeader("X-Content-Type-Options", "nosniff");
      response.end(config);
      return;
    }
    if (pathname === "/manifest.webmanifest") {
      response.statusCode = 200;
      response.setHeader("Content-Type", "application/manifest+json; charset=utf-8");
      response.setHeader("Cache-Control", "no-store");
      response.setHeader("X-Content-Type-Options", "nosniff");
      response.end(manifest);
      return;
    }
    next();
  };
}

function runtimeFilesPlugin(): Plugin {
  const install = (server: { middlewares: Connect.Server }) => {
    server.middlewares.use(runtimeMiddleware());
  };
  return {
    name: "alert-hub-runtime-files",
    configureServer: install,
    configurePreviewServer: install,
  };
}

const isCodexSeatbeltSandbox = process.env.CODEX_SANDBOX === "seatbelt";

export default defineConfig({
  plugins: [runtimeFilesPlugin(), react()],
  build: {
    target: "es2022",
  },
  server: {
    host: "127.0.0.1",
    proxy: {
      "/api": process.env.VITE_API_PROXY_TARGET ?? "http://127.0.0.1:8000",
      "/health": process.env.VITE_API_PROXY_TARGET ?? "http://127.0.0.1:8000",
      "/ingest": process.env.VITE_API_PROXY_TARGET ?? "http://127.0.0.1:8000",
      "/metrics": process.env.VITE_API_PROXY_TARGET ?? "http://127.0.0.1:8000",
    },
    watch: isCodexSeatbeltSandbox ? { useFsEvents: false, usePolling: true } : undefined,
  },
});
