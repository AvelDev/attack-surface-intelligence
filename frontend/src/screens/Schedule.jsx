import { useEffect, useState } from "react";
import { Trash2 } from "lucide-react";
import { api, can } from "../api.js";
import { useI18n } from "../i18n.jsx";
import Frame from "../components/Frame.jsx";
import Page from "../components/Page.jsx";
import { FAST, ProfileSelect, lastProfile, profileName, useNmapInfo } from "../components/NmapOptions.jsx";
import { Check, Confirm, Field, LoadState, useResource, useToast } from "../components/ui.jsx";

const INTERVALS = [6, 12, 24, 168];
const WINDOWS = [30, 60, 120];
const RATES = [100, 300, 1000];

/** Cykliczne skanowanie: każdy wpis ma stałe okno czasowe, przekroczenie przerywa przebieg. */
export default function Schedule({ user, shell, onAuthLost }) {
  const { t, n, date, ago } = useI18n();
  const { toast, flash, clear } = useToast();
  const res = useResource(api.schedules, onAuthLost, []);
  const [del, setDel] = useState(null);
  const canAdd = can(user, "add_remove_modify");
  const rows = res.data || [];

  const act = async (fn, ok) => {
    try {
      await fn();
      flash(ok, "ok");
      await res.load();
      return true;
    } catch (e) {
      onAuthLost(e);
      flash(t("err.action", { msg: e.message }), "err");
      return false;
    }
  };

  const every = (h) => (h === 24 ? t("sch.daily") : h % 168 === 0 ? t("sch.everyW", { n: h / 168 }) : h % 24 === 0 ? t("sch.everyD", { n: h / 24 }) : t("sch.everyH", { n: h }));
  const until = (ts) => {
    const s = ts - Date.now() / 1000;
    if (s <= 0) return t("sch.due");
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
    return t("time.in", { d: h ? `${h} h ${m} min` : `${m} min` });
  };

  return (
    <Page shell={shell} title={t("nav.schedule")} refreshing={res.loading} onRefresh={res.load}
          toast={toast} onToastClose={clear} className="split">
      <Frame tag="A" id="sch-list" className="split-main" title={t("sch.title")} meta={res.data ? n(rows.length) : null}>
        {!res.data ? <LoadState error={res.error} onRetry={res.load} /> : !rows.length ? (
          <p className="q-empty">{t("sch.none")}</p>
        ) : (
          <div className="t-scroll">
            <table className="d-table">
              <thead>
                <tr>
                  <th scope="col">{t("sch.target")}</th>
                  <th scope="col">{t("sch.interval")}</th>
                  <th scope="col">{t("d.window")}</th>
                  <th scope="col">{t("sch.depth")}</th>
                  <th scope="col">{t("sch.last")}</th>
                  <th scope="col">{t("sch.next")}</th>
                  {canAdd && <th scope="col"><span className="sr-only">{t("ui.delete")}</span></th>}
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => {
                  let o = {};
                  try { o = JSON.parse(r.opts || "{}"); } catch (e) { /* stary wpis */ }
                  return (
                    <tr key={r.id} className={r.enabled ? "" : "is-off"}>
                      <th scope="row" className="mono f-asset">{r.target}</th>
                      <td className="nowrap">{every(r.interval_hours)}</td>
                      <td className="mono nowrap">{r.time_window_mins} min</td>
                      <td className="nowrap">
                        <span className="mono">{o.rate_limit || 300} pps</span>
                        {o.nuclei && <span className="chip mono">nuclei</span>}
                        {o.gvm && <span className="chip mono">gvm</span>}
                        {o.nmap && <span className="chip"><span className="mono">nmap</span> {profileName(t, o.nmap).toLowerCase()}</span>}
                      </td>
                      <td className="nowrap">{r.last_run ? ago(r.last_run) : <span className="quiet">{t("d.never")}</span>}</td>
                      <td className="nowrap">
                        <span className="mono">{date(r.next_run)}</span>
                        <small className="d-sub">{r.enabled ? until(r.next_run) : t("sch.disabled")}</small>
                      </td>
                      {canAdd && (
                        <td className="d-act">
                          <button type="button" className="icon-btn btn-del" onClick={() => setDel(r)} aria-label={t("sch.deleteOf", { target: r.target })} title={t("ui.delete")}>
                            <Trash2 size={14} aria-hidden="true" />
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
      </Frame>
      <Frame tag="B" id="sch-new" className="split-side" title={t("sch.new")}>
        {canAdd ? <SchedForm onAdd={(body) => act(() => api.addSchedule(body), t("sch.added", { target: body.target }))} />
          : <p className="q-ro">{t("sch.readOnly")}</p>}
        <p className="field-hint side-note">{t("sch.note")}</p>
      </Frame>
      {del && (
        <Confirm title={t("sch.deleteTitle")} body={t("sch.deleteBody", { target: del.target })} confirmLabel={t("ui.delete")}
                 onClose={() => setDel(null)} onConfirm={() => act(() => api.deleteSchedule(del.id), t("sch.deleted"))} />
      )}
    </Page>
  );
}

function SchedForm({ onAdd }) {
  const { t } = useI18n();
  const [target, setTarget] = useState("");
  const [interval, setInterval_] = useState(24);
  const [win, setWin] = useState(60);
  const [rate, setRate] = useState(300);
  const [nuclei, setNuclei] = useState(true);
  const info = useNmapInfo();
  const [nmap, setNmap] = useState(null);
  useEffect(() => {
    const last = lastProfile();
    if (info?.installed && last !== FAST) setNmap(info.profiles.find((p) => p.profile === last) || info.profiles[0]);
  }, [info]);
  const [busy, setBusy] = useState(false);
  // Ten sam problem co w NewScan.jsx: zaznaczony checkbox dla narzędzia, którego nie ma
  // na serwerze, nic nie da - lepiej od razu go wyłączyć i powiedzieć dlaczego.
  const [tools, setTools] = useState(null);
  useEffect(() => {
    let live = true;
    api.tools().then((d) => live && setTools(d)).catch(() => {});
    return () => { live = false; };
  }, []);
  const nucleiOk = tools ? !!tools.nuclei?.installed : true;
  useEffect(() => { if (!nucleiOk) setNuclei(false); }, [nucleiOk]);

  const submit = async (e) => {
    e.preventDefault();
    if (!target.trim()) return;
    setBusy(true);
    if (await onAdd({ target: target.trim(), interval_hours: interval, time_window_mins: win, rate_limit: rate, nuclei, nmap })) setTarget("");
    setBusy(false);
  };

  return (
    <form className="form-grid side-form" onSubmit={submit}>
      <Field label={t("sch.target")} hint={t("sch.targetHint")} className="span-2">
        <input className="mono" value={target} onChange={(e) => setTarget(e.target.value)} required spellCheck={false} placeholder="10.0.0.0/24" />
      </Field>
      <Field label={t("sch.interval")}>
        <select value={interval} onChange={(e) => setInterval_(+e.target.value)}>
          {INTERVALS.map((h) => <option key={h} value={h}>{t(`sch.int${h}`)}</option>)}
        </select>
      </Field>
      <Field label={t("d.window")}>
        <select value={win} onChange={(e) => setWin(+e.target.value)}>
          {WINDOWS.map((w) => <option key={w} value={w}>{t("ns.windowN", { n: w })}</option>)}
        </select>
      </Field>
      <Field label={t("ns.rate")} className="span-2">
        <select value={rate} onChange={(e) => setRate(+e.target.value)}>
          {RATES.map((r) => <option key={r} value={r}>{t(`ns.rate${r}`)}</option>)}
        </select>
      </Field>
      <ProfileSelect info={info} value={nmap} onChange={setNmap} custom={false} />
      <div className="span-2">
        <Check checked={nuclei} onChange={setNuclei} disabled={!nucleiOk}>
          {t("ns.nuclei")}{!nucleiOk && ` — ${t("ns.unavailable")}`}
        </Check>
      </div>
      <div className="span-2 form-actions">
        <button type="submit" className="btn btn-primary" disabled={busy}>{t("sch.add")}</button>
      </div>
    </form>
  );
}
