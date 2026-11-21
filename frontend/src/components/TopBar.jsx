import { RefreshCw, Sun, Moon, LogOut, Keyboard } from "lucide-react";
import { useI18n } from "../i18n.jsx";

/** Górny pasek wspólny dla wszystkich ekranów; środek (children) należy do ekranu. */
export default function TopBar({ shell, children, refreshing, onRefresh, onShortcuts }) {
  const { t, lang, setLang } = useI18n();
  const { user, theme, onTheme, onLogout } = shell;
  return (
    <header className="top">
      <a className="brand" href="#/" aria-label="Attack Surface Intelligence">
        A<span>S</span>I
      </a>
      {children}
      {onRefresh && (
        <button type="button" className="icon-btn" onClick={onRefresh} aria-label={t("top.refresh")} title={t("top.refresh")}>
          <RefreshCw size={16} strokeWidth={1.75} className={refreshing ? "spin" : ""} aria-hidden="true" />
        </button>
      )}
      <div className="top-sp" />
      {onShortcuts && (
        <button type="button" className="icon-btn" onClick={onShortcuts} aria-label={t("top.shortcuts")} title={t("top.shortcuts")}>
          <Keyboard size={16} strokeWidth={1.75} aria-hidden="true" />
        </button>
      )}
      <div className="seg" role="group" aria-label={t("top.lang")}>
        {["pl", "en"].map((l) => (
          <button key={l} type="button" aria-pressed={lang === l} onClick={() => setLang(l)}>{l.toUpperCase()}</button>
        ))}
      </div>
      <button type="button" className="icon-btn" onClick={onTheme} aria-label={t("top.theme")} title={t("top.theme")}>
        {theme === "dark" ? <Sun size={16} strokeWidth={1.75} aria-hidden="true" /> : <Moon size={16} strokeWidth={1.75} aria-hidden="true" />}
      </button>
      <div className="who">
        <span className="who-name">{user.username}</span>
        <span className="who-role">{t(`role.${user.role}`)}</span>
      </div>
      <button type="button" className="icon-btn" onClick={onLogout} aria-label={t("top.logout")} title={t("top.logout")}>
        <LogOut size={16} strokeWidth={1.75} aria-hidden="true" />
      </button>
    </header>
  );
}
