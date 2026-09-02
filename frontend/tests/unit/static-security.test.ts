import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("static SPA security contract", () => {
  it("loads runtime configuration and application code only from external scripts", () => {
    const html = readFileSync("index.html", "utf8");
    const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
    expect(scripts).toHaveLength(2);
    for (const [, attributes, body] of scripts) {
      expect(attributes).toMatch(/\bsrc="\/[^"]+"/);
      expect(body.trim()).toBe("");
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
