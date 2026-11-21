import { useMemo, useState } from "react";
import { Pencil, Search } from "lucide-react";
import { api, SEVS } from "../api.js";
import { useI18n } from "../i18n.jsx";
import { Dialog, Field, Check, Sev } from "./ui.jsx";

const FP = "[False Positive] ";

/** Tabela ustaleń z filtrem wagi i wyszukiwaniem; wspólna dla widoku skanu i ekranu znalezisk. */
export function FindingsTable({ findings, canEdit, onEdit }) {
  const { t, n } = useI18n();
  const [sev, setSev] = useState("all");
  const [q, setQ] = useState("");
  const counts = useMemo(() => {
    const c = Object.fromEntries(SEVS.map((s) => [s, 0]));
    findings.forEach((f) => { c[f.severity] = (c[f.severity] || 0) + 1; });
    return c;
  }, [findings]);
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return findings.filter((f) => (sev === "all" || f.severity === sev) &&
      (!needle || `${f.title} ${f.asset} ${f.detail} ${f.source}`.toLowerCase().includes(needle)));
  }, [findings, sev, q]);

  return (
    <div className="ft">
      <div className="toolbar">
        <div className="seg seg-sm" role="group" aria-label={t("f.sevFilter")}>
          <button type="button" aria-pressed={sev === "all"} onClick={() => setSev("all")}>
            {t("c.all")} <span className="mono">{n(findings.length)}</span>
          </button>
          {SEVS.map((s) => (
            <button key={s} type="button" aria-pressed={sev === s} onClick={() => setSev(s)} disabled={!counts[s]}>
              {t(`sev.${s}`)} <span className="mono">{n(counts[s])}</span>
            </button>
          ))}
        </div>
        <label className="search">
          <Search size={14} aria-hidden="true" />
          <span className="sr-only">{t("f.search")}</span>
          <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder={t("f.search")} />
        </label>
      </div>
      {rows.length === 0 ? (
        <p className="q-empty">{findings.length ? t("c.emptyFiltered") : t("f.none")}</p>
      ) : (
        <div className="t-scroll">
          <table className="d-table">
            <thead>
              <tr>
                <th scope="col">{t("f.sev")}</th>
                <th scope="col">{t("f.finding")}</th>
                <th scope="col">{t("f.asset")}</th>
                <th scope="col">{t("f.fix")}</th>
                <th scope="col">{t("f.source")}</th>
                {canEdit && <th scope="col"><span className="sr-only">{t("f.edit")}</span></th>}
              </tr>
            </thead>
            <tbody>
              {rows.map((f) => {
                const fp = f.title.startsWith(FP);
                return (
                  <tr key={f.rowid} className={fp ? "is-fp" : ""}>
                    <td className="nowrap"><Sev level={f.severity} /></td>
                    <th scope="row" className="f-title">
                      <span>{fp ? f.title.slice(FP.length) : f.title}</span>
                      {fp && <span className="chip">{t("st.false_positive")}</span>}
                      {f.detail && <small>{f.detail}</small>}
                    </th>
                    <td className="mono f-asset">{f.asset}</td>
                    <td className="f-fix">{f.fix || <span className="quiet">—</span>}</td>
                    <td><span className="chip mono">{f.source}</span></td>
                    {canEdit && (
                      <td className="d-act">
                        <button type="button" className="icon-btn" onClick={() => onEdit(f)} aria-label={t("f.editOf", { title: f.title })} title={t("f.edit")}>
                          <Pencil size={14} aria-hidden="true" />
                        </button>
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/** Edycja ustalenia (pkt 14): waga, zalecenie, fałszywy alarm, trwałość decyzji między skanami. */
export function FindingDialog({ finding, onClose, onSaved, onAuthLost, flash }) {
  const { t } = useI18n();
  const fpNow = finding.title.startsWith(FP);
  const [sev, setSev] = useState(finding.severity);
  const [fix, setFix] = useState(finding.fix || "");
  const [fp, setFp] = useState(fpNow);
  const [persist, setPersist] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const save = async (e) => {
    e.preventDefault();
    setBusy(true);
    try {
      await api.editFinding(finding.rowid, { severity: sev, fix, false_positive: fp, persist_future: persist });
      flash(t("f.saved"), "ok");
      onSaved();
      onClose();
    } catch (err) {
      onAuthLost(err);
      setError(err.message);
      setBusy(false);
    }
  };

  return (
    <Dialog id="fd" title={t("f.editTitle")} onClose={onClose}
            footer={
              <>
                <button type="button" className="btn" onClick={onClose}>{t("ui.cancel")}</button>
                <button type="submit" form="fd-form" className="btn btn-primary" disabled={busy}>{t("ui.save")}</button>
              </>
            }>
      <form id="fd-form" className="form-grid" onSubmit={save}>
        <p className="dlg-subject span-2">
          <span>{fpNow ? finding.title.slice(FP.length) : finding.title}</span>
          <code>{finding.asset}</code>
        </p>
        <Field label={t("f.sev")} className="span-2">
          <select value={sev} onChange={(e) => setSev(e.target.value)} disabled={fp}>
            {SEVS.map((s) => <option key={s} value={s}>{t(`sev.${s}`)}</option>)}
          </select>
        </Field>
        <Field label={t("f.fix")} className="span-2">
          <input value={fix} onChange={(e) => setFix(e.target.value)} maxLength={1000} />
        </Field>
        <fieldset className="span-2 fs">
          <legend className="sr-only">{t("f.decision")}</legend>
          <Check checked={fp} onChange={setFp}>{t("f.markFp")}</Check>
          <Check checked={persist} onChange={setPersist}>{t("f.persist")}</Check>
        </fieldset>
        {fp && <p className="field-hint span-2">{t("f.fpHint")}</p>}
        {error && <p className="form-error span-2" role="alert">{error}</p>}
      </form>
    </Dialog>
  );
}
