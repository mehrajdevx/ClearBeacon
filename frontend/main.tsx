import { createRoot } from "react-dom/client";
import { createPortal } from "react-dom";
import { useEffect, useState } from "react";
import SculptureHero from "@/components/ui/liquid-sculpture-hero";
import { Footer } from "@/components/ui/footer";
import { readStoredTheme, THEME_STORAGE_KEY, type Theme } from "@/frontend/theme";

function requireMount(id: string): HTMLElement {
  const mount = document.getElementById(id);
  if (!mount) throw new Error(`The ClearBeacon mount point "${id}" is missing.`);
  return mount;
}

const heroMount = requireMount("sculpture-hero-root");
const themeMount = requireMount("theme-toggle-root");
const footerMount = requireMount("footer-root");
const appMount = requireMount("react-app-root");

function ThemeToggle({ theme, onToggle }: { theme: Theme; onToggle: () => void }) {
  const dark = theme === "dark";

  return (
    <button
      className="theme-toggle"
      type="button"
      aria-label={dark ? "Switch to day mode" : "Switch to night mode"}
      aria-pressed={dark}
      onClick={onToggle}
    >
      <span aria-hidden="true">{dark ? "☀" : "☾"}</span>
    </button>
  );
}

function ClearBeaconApp() {
  const [theme, setTheme] = useState<Theme>(readStoredTheme);
  const dark = theme === "dark";

  useEffect(() => {
    window.dispatchEvent(new Event("clearbeacon:react-ready"));
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    const themeColor = document.querySelector<HTMLMetaElement>('meta[name="theme-color"]');
    if (themeColor) themeColor.content = dark ? "#111110" : "#ECEBE1";

    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, theme);
    } catch (error) {
      console.warn("Could not save the display theme.", error);
    }
  }, [dark, theme]);

  const toggleTheme = () => setTheme((current) => current === "dark" ? "light" : "dark");

  return (
    <>
      {createPortal(<ThemeToggle theme={theme} onToggle={toggleTheme} />, themeMount)}
      {createPortal(
        <SculptureHero
          src="/sculpture-hero-desktop.webp"
          darkSrc="/sculpture-hero-desktop-dark.webp"
          mobileSrc="/sculpture-hero-mobile.webp"
          mobileDarkSrc="/sculpture-hero-mobile-dark.webp"
          imageAlt="A flowing metallic sculpture with particles, representing a calmer path through suspicious messages."
          imageBackground={dark ? "#111110" : "#ECEBE1"}
          brand="ClearBeacon"
          showNav={false}
          eyebrow="A calmer way to check"
          headline={"A message feels off.\nLet's look closer."}
          headlineAccent="Let's look closer."
          body="Check a suspicious link or message. See the warning signs, understand what we checked, and choose a safer next step."
          primaryCta={{ label: "Start a quick check", href: "#check" }}
          secondaryCta={{ label: "Safety guides", href: "#guides" }}
          hint=""
          hintTouch=""
          background={dark ? "#111110" : "#ECEBE1"}
          darkBackground={dark ? "#111110" : "#ECEBE1"}
          textColor={dark ? "#EEEAE2" : "#141A16"}
          accentColor={dark ? "#E1C995" : "#141A16"}
          headingFont='"DM Sans", "Segoe UI", sans-serif'
          accentFont='Georgia, "Times New Roman", serif'
          bodyFont='"DM Sans", Arial, sans-serif'
          loadFonts={false}
          theme={dark ? "dark" : "light"}
          themeToggle={false}
          interactive
          mobileSculptureScale={0.9}
          sculptureY={-2}
          particleDensity={0.8}
          height="clamp(640px, calc(100svh - 76px), 780px)"
          backdropText="CLEARBEACON"
          showCredit={false}
        />,
        heroMount,
      )}
      {createPortal(<Footer theme={theme} onToggleTheme={toggleTheme} />, footerMount)}
    </>
  );
}

createRoot(appMount).render(<ClearBeaconApp />);
