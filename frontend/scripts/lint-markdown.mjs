import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "jsonc-parser";
import { lint } from "markdownlint/sync";

const root = join(dirname(fileURLToPath(import.meta.url)), "../..");
const excluded = new Set([".git", ".venv", "node_modules", "dist"]);
function markdownFiles(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      return excluded.has(entry.name) ? [] : markdownFiles(path);
    }
    return entry.isFile() && entry.name.endsWith(".md") ? [path] : [];
  });
}
const files = markdownFiles(root).sort();
const parseErrors = [];
const { config } = parse(
  readFileSync(join(root, ".markdownlint-cli2.jsonc"), "utf8"),
  parseErrors,
  { allowTrailingComma: true },
);
if (parseErrors.length || !config || typeof config !== "object") {
  throw new Error("Invalid Markdown lint configuration");
}
const result = lint({ files, config });
const errors = Object.entries(result).flatMap(([path, issues]) =>
  issues.map(
    (issue) => `${path}:${issue.lineNumber} ${issue.ruleNames.join("/")} ${issue.errorDescription}`,
  ),
);
console.log(`Markdown: ${files.length} files`);
if (errors.length) {
  console.error(errors.join("\n"));
  process.exitCode = 1;
}
