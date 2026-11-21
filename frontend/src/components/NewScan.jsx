import { useRef, useState } from "react";
import { FileUp } from "lucide-react";
import { api } from "../api.js";
import { useI18n } from "../i18n.jsx";
import { Dialog, Field, Check } from "./ui.jsx";

const RATES = [100, 300, 1000];
const WINDOWS = [0, 15, 60, 120];

/** Nowy zakres / skan: cele ręcznie albo z pliku, tempo, okno czasowe, głębokość, zgoda. */
export default function NewScan({ onClose, onStarted, onAuthLost, flash, initial }) {
  const { t } = useI18n();
  const [targets, setTargets] = useState(initial?.targets || "");
  const [rate, setRate] = useState(initial?.rate || 300);
  const [win, setWin] = useState(initial?.window || 0);
  const [nuclei, setNuclei] = useState(initial?.nuclei ?? true);
  const [gvm, setGvm] = useState(initial?.gvm ?? false);
  const [auth, setAuth] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const fileRef = useRef(null);

  const list = targets.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);

  const done = (r) => {
    if (r.warnings?.length) flash(t("ns.warnings", { n: r.warnings.length, first: r.warnings[0] }), "err");
    else flash(t("ns.started", { id: r.id }), "ok");
    onStarted(r.id);
    onClose();
  };

  const fail = (e) => {
    onAuthLost(e);
    setError(e.message);
    setBusy(false);
  };

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    if (!list.length) return setError(t("ns.errEmpty"));
    if (!auth) return setError(t("ns.errAuth"));
    setBusy(true);
    try {
      done(await api.startScan({ targets: list, authorized: true, nuclei, gvm, rate_limit: rate, time_window_mins: win || null }));
    } catch (err) { fail(err); }
  };

  const onFile = async (e) => {
    const file = e.target.files[0];
    e.target.value = "";
    if (!file) return;
    setError("");
    if (!auth) return setError(t("ns.errAuth"));
    const fd = new FormData();
    fd.append("file", file);
    fd.append("authorized", "true");
    fd.append("nuclei", nuclei ? "true" : "false");
    fd.append("gvm", gvm ? "true" : "false");
    setBusy(true);
    try { done(await api.importTargets(fd)); } catch (err) { fail(err); }
  };

  return (
    <Dialog id="ns" title={t("ns.title")} onClose={onClose} wide
            footer={
              <>
                <button type="button" className="btn" onClick={() => fileRef.current.click()} disabled={busy}>
                  <FileUp size={14} aria-hidden="true" /> {t("ns.import")}
                </button>
                <input ref={fileRef} type="file" accept=".csv,.json,.txt" hidden onChange={onFile} />
                <span className="dlg-sp" />
                <button type="button" className="btn" onClick={onClose}>{t("ui.cancel")}</button>
                <button type="submit" form="ns-form" className="btn btn-primary" disabled={busy}>
                  {busy ? t("ns.starting") : list.length > 1 ? t("ns.startN", { n: list.length }) : t("ns.start")}
                </button>
              </>
            }>
      <form id="ns-form" className="form-grid" onSubmit={submit}>
        <Field label={t("ns.targets")} hint={t("ns.targetsHint")} className="span-2">
          <textarea className="mono" rows={5} value={targets} onChange={(e) => setTargets(e.target.value)}
                    placeholder={"10.0.0.0/24\nlab.example.org\n192.0.2.14"} autoFocus spellCheck={false} />
        </Field>
        <Field label={t("ns.rate")}>
          <select value={rate} onChange={(e) => setRate(+e.target.value)}>
            {RATES.map((r) => <option key={r} value={r}>{t(`ns.rate${r}`)}</option>)}
          </select>
        </Field>
        <Field label={t("ns.window")} hint={t("ns.windowHint")}>
          <select value={win} onChange={(e) => setWin(+e.target.value)}>
            {WINDOWS.map((w) => <option key={w} value={w}>{w ? t("ns.windowN", { n: w }) : t("ns.windowNone")}</option>)}
          </select>
        </Field>
        <fieldset className="span-2 fs">
          <legend>{t("ns.depth")}</legend>
          <Check checked={nuclei} onChange={setNuclei}>{t("ns.nuclei")}</Check>
          <Check checked={gvm} onChange={setGvm}>{t("ns.gvm")}</Check>
        </fieldset>
        <div className="span-2 consent">
          <Check checked={auth} onChange={setAuth}>{t("ns.auth")}</Check>
        </div>
        {error && <p className="form-error span-2" role="alert">{error}</p>}
      </form>
    </Dialog>
  );
}
