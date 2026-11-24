import { useCallback, useEffect, useRef, useState } from "react";
import { X, TriangleAlert } from "lucide-react";
import { useI18n } from "../i18n.jsx";
import { SEVS } from "../api.js";

/* Wspólne klocki ekranów: dialog, potwierdzenie, toast, waga, stan skanu, pusta lista. */

export function Dialog({ id, title, tag, onClose, children, footer, wide = false }) {
  const ref = useRef(null);
  useEffect(() => {
    const d = ref.current;
    d.showModal();
    const onCancel = (e) => { e.preventDefault(); onClose(); };
    d.addEventListener("cancel", onCancel);
    return () => d.removeEventListener("cancel", onCancel);
  }, [onClose]);
  return (
    <dialog ref={ref} className={`mod dlg${wide ? " dlg-wide" : ""}`} aria-labelledby={`${id}-h`}
            onMouseDown={(e) => e.target === ref.current && onClose()}>
      {tag && <span className="mod-tag" aria-hidden="true">{tag}</span>}
      <h2 className="mod-title dlg-title" id={`${id}-h`}>{title}</h2>
      <div className="dlg-body">{children}</div>
      {footer && <div className="dlg-foot">{footer}</div>}
    </dialog>
  );
}

export function Confirm({ title, body, confirmLabel, onConfirm, onClose }) {
  const { t } = useI18n();
  const [busy, setBusy] = useState(false);
  return (
    <Dialog id="confirm" title={title} onClose={onClose}
            footer={
              <>
                <button type="button" className="btn" onClick={onClose} autoFocus>{t("ui.cancel")}</button>
                <button type="button" className="btn btn-danger" disabled={busy}
                        onClick={async () => { setBusy(true); await onConfirm(); setBusy(false); onClose(); }}>
                  {confirmLabel}
                </button>
              </>
            }>
      <p className="dlg-text">{body}</p>
    </Dialog>
  );
}

/** Toast: potwierdzenia znikają po 5 s, błąd zostaje, aż operator go zamknie. */
export function useToast() {
  const [toast, setToast] = useState(null);
  const flash = useCallback((msg, tone = "info") => setToast({ msg, tone, at: Date.now() }), []);
  useEffect(() => {
    if (!toast || toast.tone === "err") return;
    const h = setTimeout(() => setToast(null), 5000);
    return () => clearTimeout(h);
  }, [toast]);
  return { toast, flash, clear: () => setToast(null) };
}

export function ToastRegion({ toast, onClose }) {
  const { t } = useI18n();
  return (
    <div className="toast-region" aria-live="polite">
      {toast && (
        <div className={`toast toast-${toast.tone}`} key={toast.at} role={toast.tone === "err" ? "alert" : undefined}>
          <span>{toast.msg}</span>
          <button type="button" className="toast-x" onClick={onClose} aria-label={t("keys.close")}><X size={14} aria-hidden="true" /></button>
        </div>
      )}
    </div>
  );
}

/** Waga jako iglica: liczba słupków rośnie z wagą, czerwień tylko dla krytycznej. */
export function Sev({ level, compact = false }) {
  const { t } = useI18n();
  const rank = Math.max(0, 4 - SEVS.indexOf(level));
  return (
    <span className={`sev sev-${level}`}>
      {level === "critical" ? (
        <TriangleAlert size={13} strokeWidth={2} aria-hidden="true" />
      ) : (
        <span className="sev-bars" aria-hidden="true">
          {[1, 2, 3].map((i) => <i key={i} className={i <= rank ? "on" : ""} />)}
        </span>
      )}
      <span className={compact ? "sr-only" : ""}>{t(`sev.${level}`)}</span>
    </span>
  );
}

export function ScanState({ status, pct }) {
  const { t } = useI18n();
  return (
    <span className={`d-state st-${status}`}>
      <i aria-hidden="true" />
      {status === "running" && pct != null ? t("state.running", { pct }) : t(`state.${status}`)}
    </span>
  );
}

export function Empty({ title, children }) {
  return (
    <div className="empty">
      <span className="empty-field" aria-hidden="true" />
      <p className="empty-title">{title}</p>
      {children}
    </div>
  );
}

export function Field({ label, hint, children, className = "", action }) {
  return (
    <label className={`field ${className}`}>
      {action ? <span className="field-head"><span>{label}</span>{action}</span> : <span>{label}</span>}
      {children}
      {hint && <small className="field-hint">{hint}</small>}
    </label>
  );
}

/** Komenda z łamaniem między argumentami, nigdy w środku flagi. */
export function Command({ text, children }) {
  return <code className="cmd">{text.split(" ").map((arg, i) => <span key={i}>{arg} </span>)}{children}</code>;
}

export function Check({ checked, onChange, children, disabled }) {
  return (
    <label className="check">
      <input type="checkbox" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <span>{children}</span>
    </label>
  );
}

/** Ładowanie listy z API z obsługą błędu i 401 (utrata sesji). */
export function useResource(fetcher, onAuthLost, deps = []) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const reqId = useRef(0);
  const load = useCallback(async () => {
    const id = ++reqId.current;
    setLoading(true);
    try {
      const d = await fetcher();
      if (id !== reqId.current) return;
      setData(d);
      setError(null);
    } catch (e) {
      if (id !== reqId.current) return;
      onAuthLost(e);
      setError(e.message);
    } finally {
      if (id === reqId.current) setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => { load(); }, [load]);
  return { data, error, loading, load, setData };
}

export function LoadState({ error, onRetry, rows = 4 }) {
  const { t } = useI18n();
  if (error) {
    return (
      <div className="load-error inline" role="alert">
        <p>{t("err.load", { msg: error })}</p>
        <button type="button" className="btn" onClick={onRetry}>{t("err.retry")}</button>
      </div>
    );
  }
  return (
    <div className="skel-rows" aria-hidden="true">
      {Array.from({ length: rows }, (_, i) => <span key={i} className="skel-line" style={{ width: `${70 - i * 9}%` }} />)}
    </div>
  );
}
