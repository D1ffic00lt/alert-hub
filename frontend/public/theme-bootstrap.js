/* global document, window */
/* Apply a device theme before React loads to avoid a light/dark flash. */
(() => {
  const storageKey = "alert-hub-ui-theme";
  const languageStorageKey = "alert-hub-ui-language";
  let preference = "dark";
  let language = "en";
  try {
    const saved = window.localStorage.getItem(storageKey);
    if (saved === "light" || saved === "dark" || saved === "system") preference = saved;
    const savedLanguage = window.localStorage.getItem(languageStorageKey);
    if (savedLanguage === "ru" || savedLanguage === "en") language = savedLanguage;
  } catch {
    // Storage can be unavailable; the system preference is still usable.
  }
  const prefersDark = window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? true;
  const resolved = preference === "system" ? (prefersDark ? "dark" : "light") : preference;
  const root = document.documentElement;
  root.lang = language;
  root.dataset.theme = resolved;
  root.dataset.themePreference = preference;
  root.style.colorScheme = resolved;
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute("content", resolved === "dark" ? "#0A0A0B" : "#FFFFFF");
})();
