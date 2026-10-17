export type Theme = "light" | "dark";

export const THEME_STORAGE_KEY = "clearbeacon-theme";

export function readStoredTheme(): Theme {
  try {
    return window.localStorage.getItem(THEME_STORAGE_KEY) === "dark" ? "dark" : "light";
  } catch (error) {
    console.warn("Could not read the saved display theme.", error);
    return "light";
  }
}
