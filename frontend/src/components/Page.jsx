import { useEffect, useState } from "react";
import { api } from "../api.js";
import { useI18n } from "../i18n.jsx";
import TopBar from "./TopBar.jsx";
import { ToastRegion } from "./ui.jsx";

/** Rama ekranu poza przeglądem: pasek z nazwą ekranu, treść, pasek stanu narzędzi, toast. */
export default function Page({ shell, title, sub, refreshing, onRefresh, toast, onToastClose, className = "", children }) {
  useEffect(() => { document.title = `ASI · ${title}`; }, [title]);
  return (
    <>
      <TopBar shell={shell} refreshing={refreshing} onRefresh={onRefresh}>
        <h1 className="top-title">{title}</h1>
        {sub && <span className="top-pass">{sub}</span>}
      </TopBar>
      <main id="main" className={`page ${className}`}>{children}</main>
      <ToolTick />
      <ToastRegion toast={toast} onClose={onToastClose} />
    </>
  );
}

const ORDER = ["nmap", "subfinder", "dnsx", "naabu", "httpx", "nuclei", "openvas", "defectdojo"];

/** Stopka: które narzędzia są w obrazie, a gdzie działa zamiennik w Pythonie. */
function ToolTick() {
  const { t } = useI18n();
  const [tools, setTools] = useState(null);
  useEffect(() => {
    let live = true;
    api.tools().then((d) => live && setTools(d)).catch(() => {});
    return () => { live = false; };
  }, []);
  if (!tools) return <footer className="tick" />;
  const names = [...ORDER.filter((k) => tools[k]), ...Object.keys(tools).filter((k) => !ORDER.includes(k))];
  return (
    <footer className="tick">
      <span className="tick-label">{t("tick.tools")}</span>
      {names.map((k) => (
        <span key={k} title={tools[k].installed ? t("tools.installed") : t("tools.fallback")}>
          <i className={`tk ${tools[k].installed ? "tk-ink" : "tk-hollow"}`} aria-hidden="true" />
          <span className="mono">{k}</span>
          <span className="sr-only">{tools[k].installed ? t("tools.installed") : t("tools.fallback")}</span>
        </span>
      ))}
      <span className="tick-sp" />
      <span className="tick-key">
        <span><i className="tk tk-ink" aria-hidden="true" />{t("tools.installed")}</span>
        <span><i className="tk tk-hollow" aria-hidden="true" />{t("tools.fallback")}</span>
      </span>
    </footer>
  );
}
