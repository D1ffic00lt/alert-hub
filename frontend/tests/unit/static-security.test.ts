import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("static SPA security contract", () => {
  it("declares English defaults while preserving the product brand", () => {
    const html = readFileSync("index.html", "utf8");
    expect(html).toContain('<html lang="en">');
    expect(html).toContain('<meta name="theme-color" content="#0A0A0B" />');
    expect(html).toContain('<meta name="color-scheme" content="light dark" />');
    expect(html).toContain("<title>Alert Hub — Monitoring center</title>");
    expect(html).toContain('<meta property="og:title" content="Alert Hub — Monitoring center" />');
  });

  it("loads runtime configuration and application code only from external scripts", () => {
    const html = readFileSync("index.html", "utf8");
    const approvedScripts = [
      '<script src="/theme-bootstrap.js"></script>',
      '<script vite-ignore src="/runtime-config.js"></script>',
      '<script type="module" src="/app/main.tsx"></script>',
    ];
    expect(html.toLowerCase().split("<script")).toHaveLength(approvedScripts.length + 1);
    for (const script of approvedScripts) {
      expect(html).toContain(script);
    }
  });

  it("keeps unsafe-inline out of script-src in every shipped proxy", () => {
    for (const path of [
      new URL("../../container/nginx.conf", import.meta.url),
      new URL("../../../nginx.conf.example", import.meta.url),
      new URL("../../../Caddyfile.example", import.meta.url),
    ]) {
      const config = readFileSync(path, "utf8");
      expect(config).toContain("script-src 'self'");
      expect(config).not.toMatch(/script-src[^;"]*'unsafe-inline'/);
    }
  });

  it("uses a mode-specific shell guard while API routes fail closed", () => {
    const nginx = readFileSync(new URL("../../container/nginx.conf", import.meta.url), "utf8");
    const renderer = readFileSync(
      new URL("../../container/render-ui-runtime.sh", import.meta.url),
      "utf8",
    );
    const unavailable = readFileSync("public/service-unavailable.html", "utf8");
    expect(nginx).toContain("server alert-hub:8080;");
    expect(nginx).toContain("include /run/alert-hub/ui/shell-guard.conf;");
    expect(renderer).toContain("auth_request /_api_ready;");
    expect(nginx).toContain("return 503");
    expect(nginx).not.toContain("proxy_connect_timeout 5s;");
    expect(renderer).toContain("error_page 500 502 503 504 =503 /service-unavailable.html;");
    expect(nginx).toContain("location = /service-unavailable.html");
    expect(nginx).toMatch(/location = \/service-unavailable\.html \{\s+internal;/);
    expect(nginx).not.toContain("127.0.0.1:8000");
    expect(unavailable).toContain("data-service-unavailable");
    expect(unavailable).toContain("API offline · HTTP 503");
    expect(unavailable.toLowerCase()).not.toContain("<script");
  });
});
