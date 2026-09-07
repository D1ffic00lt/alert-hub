import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import vm from "node:vm";
import { describe, expect, it } from "vitest";

const renderer = fileURLToPath(new URL("../../container/render-ui-runtime.sh", import.meta.url));

function render(appName: string | undefined, env: Record<string, string> = {}) {
  const destination = mkdtempSync(join(tmpdir(), "alert-hub-ui-"));
  execFileSync("/bin/sh", [renderer, destination], {
    env: {
      ...process.env,
      APP_NAME: appName,
      API_HA_MODE: "single",
      NODE_PUBLIC_API_URL: "",
      PUBLIC_API_CANDIDATES: "",
      ...env,
    },
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
        apiHaMode: string;
        nodePublicApiUrl: string | null;
        publicApiCandidates: string[];
      };
      expect(config.appName).toBe("North<script> Ops Line");
      expect(config).toMatchObject({
        apiHaMode: "single",
        nodePublicApiUrl: null,
        publicApiCandidates: [],
      });
      expect(vm.runInContext("Object.isFrozen(globalThis.__ALERT_HUB_CONFIG__)", context)).toBe(
        true,
      );
      expect(manifest.name).toBe(config.appName);
      expect(manifest.short_name).toBe(config.appName.slice(0, 24));
      expect(manifest).toMatchObject({
        background_color: "#0A0A0B",
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
        theme_color: "#0A0A0B",
      });
      expect(manifest.icons.map((icon) => icon.purpose)).toEqual(["any", "maskable"]);
      expect(statSync(scriptPath).mode & 0o777).toBe(0o444);
      expect(statSync(manifestPath).mode & 0o777).toBe(0o444);
    } finally {
      rmSync(destination, { recursive: true, force: true });
    }
  });

  it("renders an immutable, server-owned client-failover candidate set", () => {
    const destination = render("Alert Hub", {
      API_HA_MODE: "client-failover",
      NODE_PUBLIC_API_URL: "https://api-ru.alerts.example/",
      PUBLIC_API_CANDIDATES:
        "https://api-ru.alerts.example,https://api-nl.alerts.example,https://api-de.alerts.example",
    });
    try {
      const script = readFileSync(join(destination, "runtime-config.js"), "utf8");
      const context = vm.createContext({});
      vm.runInContext(script, context);
      const config = vm.runInContext("globalThis.__ALERT_HUB_CONFIG__", context) as {
        apiHaMode: string;
        nodePublicApiUrl: string;
        publicApiCandidates: string[];
      };
      expect(config).toMatchObject({
        apiHaMode: "client-failover",
        nodePublicApiUrl: "https://api-ru.alerts.example",
        publicApiCandidates: [
          "https://api-ru.alerts.example",
          "https://api-nl.alerts.example",
          "https://api-de.alerts.example",
        ],
      });
      expect(
        vm.runInContext("Object.isFrozen(__ALERT_HUB_CONFIG__.publicApiCandidates)", context),
      ).toBe(true);
      expect(readFileSync(join(destination, "shell-guard.conf"), "utf8")).not.toContain(
        "auth_request",
      );
    } finally {
      rmSync(destination, { recursive: true, force: true });
    }
  });

  it("rejects unsafe or missing client-failover origins", () => {
    expect(() =>
      render("Alert Hub", {
        API_HA_MODE: "client-failover",
        PUBLIC_API_CANDIDATES: "https://api.example/path",
      }),
    ).toThrow();
    expect(() =>
      render("Alert Hub", {
        API_HA_MODE: "client-failover",
        PUBLIC_API_CANDIDATES: "https://api.example,https://api.example",
      }),
    ).toThrow();
    expect(() => render("Alert Hub", { API_HA_MODE: "client-failover" })).toThrow();
  });

  it("can bootstrap client failover from the unique node API origin alone", () => {
    const destination = render("Alert Hub", {
      API_HA_MODE: "client-failover",
      NODE_PUBLIC_API_URL: "https://api-ru.alerts.example",
    });
    try {
      const script = readFileSync(join(destination, "runtime-config.js"), "utf8");
      const context = vm.createContext({});
      vm.runInContext(script, context);
      const config = vm.runInContext("globalThis.__ALERT_HUB_CONFIG__", context) as {
        nodePublicApiUrl: string;
        publicApiCandidates: string[];
      };
      expect(config).toMatchObject({
        nodePublicApiUrl: "https://api-ru.alerts.example",
        publicApiCandidates: [],
      });
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
