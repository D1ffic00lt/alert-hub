import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("static SPA security contract", () => {
  it("declares Russian document metadata while preserving the product brand", () => {
    const html = readFileSync("index.html", "utf8");
    expect(html).toContain('<html lang="ru">');
    expect(html).toContain('<meta name="theme-color" content="#0b0f0e" />');
    expect(html).toContain("<title>Alert Hub — консоль мониторинга</title>");
    expect(html).toContain(
      '<meta property="og:title" content="Alert Hub — консоль мониторинга" />',
    );
  });

  it("loads runtime configuration and application code only from external scripts", () => {
    const html = readFileSync("index.html", "utf8");
    const approvedScripts = [
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

  it("guards the web shell with API readiness and a recoverable 503", () => {
    const nginx = readFileSync(new URL("../../container/nginx.conf", import.meta.url), "utf8");
    expect(nginx).toContain("server alert-hub:8080;");
    expect(nginx).toContain("auth_request /_api_ready;");
    expect(nginx).toContain("return 503");
    expect(nginx).not.toContain("127.0.0.1:8000");
  });
});
