import { readFileSync } from "node:fs";
import vm from "node:vm";
import { describe, expect, it } from "vitest";

const bootstrap = readFileSync("public/theme-bootstrap.js", "utf8");

function runBootstrap(saved: Record<string, string> = {}, prefersDark = false) {
  const root = {
    dataset: {} as Record<string, string>,
    lang: "",
    style: {} as Record<string, string>,
  };
  let metaColor = "";
  vm.runInNewContext(bootstrap, {
    document: {
      documentElement: root,
      querySelector: () => ({
        setAttribute: (_name: string, value: string) => {
          metaColor = value;
        },
      }),
    },
    window: {
      localStorage: {
        getItem: (key: string) => saved[key] ?? null,
      },
      matchMedia: () => ({ matches: prefersDark }),
    },
  });
  return { metaColor, root };
}

describe("early interface bootstrap", () => {
  it("defaults a new browser to English and the dark theme", () => {
    const { metaColor, root } = runBootstrap();
    expect(root.lang).toBe("en");
    expect(root.dataset).toEqual({ theme: "dark", themePreference: "dark" });
    expect(root.style.colorScheme).toBe("dark");
    expect(metaColor).toBe("#0A0A0B");
  });

  it("restores saved language and system theme choices", () => {
    const { metaColor, root } = runBootstrap(
      {
        "alert-hub-ui-language": "ru",
        "alert-hub-ui-theme": "system",
      },
      false,
    );
    expect(root.lang).toBe("ru");
    expect(root.dataset).toEqual({ theme: "light", themePreference: "system" });
    expect(metaColor).toBe("#FFFFFF");
  });
});
