import type { Theme } from "@/frontend/theme";

interface FooterdemoProps {
  theme: Theme;
  onToggleTheme: () => void;
}

export function Footerdemo({ theme, onToggleTheme }: FooterdemoProps) {
  const dark = theme === "dark";

  return (
    <footer className="site-footer">
      <div className="footer-main">
        <div className="footer-about">
          <a className="brand footer-brand" href="/" aria-label="ClearBeacon home">
            <span className="brand-mark" aria-hidden="true">C</span>
            <span>Clear<span className="brand-accent">Beacon</span></span>
          </a>
          <p data-i18n="footerIntro">
            An independent, educational decision-support project. No result guarantees that a link or message is safe.
          </p>
          <button
            className="footer-theme-toggle"
            type="button"
            aria-label={dark ? "Switch to day mode" : "Switch to night mode"}
            aria-pressed={dark}
            onClick={onToggleTheme}
          >
            <span aria-hidden="true">{dark ? "☀" : "☾"}</span>
            {dark ? "Day mode" : "Night mode"}
          </button>
        </div>

        <nav className="footer-column" aria-label="Explore ClearBeacon">
          <h2>Explore</h2>
          <a href="#check" data-i18n="footerCheck">Check</a>
          <a href="#guides" data-i18n="footerGuides">Safety tips</a>
          <a href="#safety-center" data-i18n="footerHelp">Official help ↗</a>
          <a href="#report" data-i18n="footerReport">Report</a>
        </nav>

        <nav className="footer-column" aria-label="Project information">
          <h2>Information</h2>
          <a href="/privacy.html">Privacy notice</a>
          <a href="/privacy.html">How checks work</a>
          <a href="#main">Back to top ↑</a>
        </nav>
      </div>

      <div className="footer-bottom">
        <p data-i18n="footerDisclaimer">
          ClearBeacon is not affiliated with any government service.
        </p>
        <small>
          ClearBeacon is not affiliated with any government agency. Its provisional name has not been cleared for public use.
        </small>
        <span>© {new Date().getFullYear()} ClearBeacon</span>
      </div>
    </footer>
  );
}
