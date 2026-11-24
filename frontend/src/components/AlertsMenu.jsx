import { useCallback, useEffect, useRef, useState } from "react";
import { Bell } from "lucide-react";
import { api } from "../api.js";
import { useI18n } from "../i18n.jsx";

const POLL_MS = 60000;

/** Alerty po skanach (nowe pilne problemy, pogorszenie oceny, nowe adresy): dzwonek z licznikiem i lista. */
export default function AlertsMenu({ onAuthLost }) {
  const { t } = useI18n();
  const [data, setData] = useState({ unread: 0, items: [] });
  const [open, setOpen] = useState(false);
  const box = useRef(null);

  const load = useCallback(() => {
    api.alerts().then(setData).catch((e) => onAuthLost && onAuthLost(e));
  }, [onAuthLost]);

  useEffect(() => {
    load();
    const id = setInterval(load, POLL_MS);
    return () => clearInterval(id);
  }, [load]);

  useEffect(() => {
    if (!open) return undefined;
    const close = (e) => { if (box.current && !box.current.contains(e.target)) setOpen(false); };
    const esc = (e) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", esc);
    return () => { document.removeEventListener("mousedown", close); document.removeEventListener("keydown", esc); };
  }, [open]);

  const toggle = () => {
    const next = !open;
    setOpen(next);
    if (next && data.unread) api.readAlerts().then(() => setData((d) => ({ ...d, unread: 0 }))).catch(() => {});
  };

  return (
    <div className="alerts" ref={box}>
      <button type="button" className="icon-btn" onClick={toggle} aria-expanded={open} aria-haspopup="true"
              aria-label={t("al.title")} title={t("al.title")}>
        <Bell size={16} strokeWidth={1.75} aria-hidden="true" />
        {data.unread > 0 && <span className="alerts-badge" aria-label={t("al.unread", { n: data.unread })}>{data.unread > 9 ? "9+" : data.unread}</span>}
      </button>
      {open && (
        <div className="alerts-pop" role="region" aria-label={t("al.title")}>
          <h2>{t("al.title")}</h2>
          {data.items.length === 0 ? <p className="alerts-empty">{t("al.empty")}</p> : (
            <ul>
              {data.items.map((a) => (
                <li key={a.id} className={`alert-${a.level}`}>
                  <a href={`#/scans/${a.scan_id}`} onClick={() => setOpen(false)}>
                    <b className="mono">{a.target}</b>
                    <span>{a.message}</span>
                    <time dateTime={new Date(a.created * 1000).toISOString()}>{new Date(a.created * 1000).toLocaleString()}</time>
                  </a>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
