import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import vm from "node:vm";
import { describe, expect, it } from "vitest";

const renderer = fileURLToPath(new URL("../../container/render-ui-runtime.sh", import.meta.url));

function render(appName: string | undefined) {
  const destination = mkdtempSync(join(tmpdir(), "alert-hub-ui-"));
  execFileSync("/bin/sh", [renderer, destination], {
    env: { ...process.env, APP_NAME: appName },
  });
  return destination;
}

describe("container UI runtime renderer", () => {
  it("atomically renders an inert APP_NAME config and matching manifest", () => {
    const destination = render("  North<script>\n Ops\u2028Line  ");

    try {
      const scriptPath = join(destination, "runtime-config.js");
      const manifestPath = join(destination, "manifest.webmanifest");
      const script = readFileSync(scriptPath, "utf8");
      const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
        background_color: string;
        description: string;
        name: string;
        short_name: string;
        icons: Array<{ purpose: string }>;
        shortcuts: Array<{ description: string; name: string; short_name: string; url: string }>;
        theme_color: string;
      };

      expect(script).not.toContain("<script>");
      expect(script).not.toContain("\u2028");
      expect([...script].every((character) => character.codePointAt(0)! <= 0x7f)).toBe(true);
      const context = vm.createContext({});
      vm.runInContext(script, context);
      const config = vm.runInContext("globalThis.__ALERT_HUB_CONFIG__", context) as {
        appName: string;
      };
      expect(config.appName).toBe("North<script> Ops Line");
      expect(vm.runInContext("Object.isFrozen(globalThis.__ALERT_HUB_CONFIG__)", context)).toBe(
        true,
      );
      expect(manifest.name).toBe(config.appName);
      expect(manifest.short_name).toBe(config.appName.slice(0, 24));
      expect(manifest).toMatchObject({
        background_color: "#0b0f0e",
        description: "Распределённый мониторинг инцидентов и отказоустойчивая доставка оповещений.",
        shortcuts: [
          {
            description: "Открыть список активных инцидентов",
            name: "Активные инциденты",
            short_name: "Инциденты",
            url: "/incidents",
          },
          {
            description: "Проверить синхронизацию узлов",
            name: "Состояние кластера",
            short_name: "Кластер",
            url: "/cluster",
          },
        ],
        theme_color: "#0b0f0e",
      });
      expect(manifest.icons.map((icon) => icon.purpose)).toEqual(["any", "maskable"]);
      expect(statSync(scriptPath).mode & 0o777).toBe(0o444);
      expect(statSync(manifestPath).mode & 0o777).toBe(0o444);
    } finally {
      rmSync(destination, { recursive: true, force: true });
    }
  });

  it("uses the product default when APP_NAME is blank", () => {
    const destination = render(" \n\t ");
    try {
      const manifest = JSON.parse(
        readFileSync(join(destination, "manifest.webmanifest"), "utf8"),
      ) as { name: string; short_name: string };
      expect(manifest).toMatchObject({ name: "Alert Hub", short_name: "Alert Hub" });
    } finally {
      rmSync(destination, { recursive: true, force: true });
    }
  });

  it("truncates names by Unicode code points without splitting astral characters", () => {
    const destination = render("😀".repeat(90));
    try {
      const manifest = JSON.parse(
        readFileSync(join(destination, "manifest.webmanifest"), "utf8"),
      ) as { name: string; short_name: string };
      expect([...manifest.name]).toHaveLength(80);
      expect([...manifest.short_name]).toHaveLength(24);
      expect(manifest.name).toBe("😀".repeat(80));
      expect(manifest.short_name).toBe("😀".repeat(24));
    } finally {
      rmSync(destination, { recursive: true, force: true });
    }
  });
});
