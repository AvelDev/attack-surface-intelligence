import { useState } from "react";
import { Trash2 } from "lucide-react";
import { api, can, SEVS } from "../api.js";
import { useI18n } from "../i18n.jsx";
import Frame from "../components/Frame.jsx";
import Page from "../components/Page.jsx";
import { Confirm, Field, LoadState, Sev, useResource, useToast } from "../components/ui.jsx";

const TYPES = ["header_present", "cookie_name", "html_regex", "footer_version_regex", "path_check", "favicon_hash"];

/** Własne sygnatury (pkt 10): lista z przełącznikiem aktywności i formularz nowej reguły. */
export default function Signatures({ user, shell, onAuthLost }) {
  const { t, n } = useI18n();
  const { toast, flash, clear } = useToast();
  const res = useResource(api.signatures, onAuthLost, []);
  const [del, setDel] = useState(null);
  const canAdd = can(user, "add_remove_modify");
  const canToggle = can(user, "read_modify");
  const sigs = res.data || [];

  const act = async (fn, ok) => {
    try {
      await fn();
      if (ok) flash(ok, "ok");
      await res.load();
      return true;
    } catch (e) {
      onAuthLost(e);
      flash(t("err.action", { msg: e.message }), "err");
      return false;
    }
  };

  const toggle = (s) => act(() => api.updateSignature(s.id, { ...s, enabled: !s.enabled }));
  const active = sigs.filter((s) => s.enabled).length;

  return (
    <Page shell={shell} title={t("nav.signatures")} refreshing={res.loading} onRefresh={res.load}
          toast={toast} onToastClose={clear} className="split">
      <Frame tag="A" id="sig-list" className="split-main" title={t("sig.title")}
             meta={res.data ? t("sig.meta", { n: n(sigs.length), on: n(active) }) : null}>
        {!res.data ? <LoadState error={res.error} onRetry={res.load} /> : !sigs.length ? (
          <p className="q-empty">{t("sig.none")}</p>
        ) : (
          <div className="t-scroll">
            <table className="d-table">
              <thead>
                <tr>
                  <th scope="col">{t("sig.name")}</th>
                  <th scope="col">{t("sig.type")}</th>
                  <th scope="col">{t("sig.pattern")}</th>
                  <th scope="col">{t("f.sev")}</th>
                  <th scope="col">{t("sig.enabled")}</th>
                  {canAdd && <th scope="col"><span className="sr-only">{t("ui.delete")}</span></th>}
                </tr>
              </thead>
              <tbody>
                {sigs.map((s) => (
                  <tr key={s.id} className={s.enabled ? "" : "is-off"}>
                    <th scope="row" className="f-title">
                      <span>{s.name}</span>
                      {(s.title || s.fix) && <small>{s.title || s.fix}</small>}
                    </th>
                    <td className="mono nowrap">{s.type}</td>
                    <td className="mono f-asset">{s.pattern}</td>
                    <td className="nowrap"><Sev level={s.severity} /></td>
                    <td>
                      <label className="switch">
                        <input type="checkbox" role="switch" checked={!!s.enabled} disabled={!canToggle} onChange={() => toggle(s)}
                               aria-label={t("sig.toggle", { name: s.name })} />
                        <span aria-hidden="true">{s.enabled ? t("sig.on") : t("sig.off")}</span>
                      </label>
                    </td>
                    {canAdd && (
                      <td className="d-act">
                        <button type="button" className="icon-btn btn-del" onClick={() => setDel(s)} aria-label={t("sig.deleteOf", { name: s.name })} title={t("ui.delete")}>
                          <Trash2 size={14} aria-hidden="true" />
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Frame>
      <Frame tag="B" id="sig-new" className="split-side" title={canAdd ? t("sig.new") : t("sig.types")}>
        {canAdd ? <SigForm onAdd={(body) => act(() => api.addSignature(body), t("sig.added", { name: body.name }))} /> : <TypeList />}
      </Frame>
      {del && (
        <Confirm title={t("sig.deleteTitle")} body={t("sig.deleteBody", { name: del.name })} confirmLabel={t("ui.delete")}
                 onClose={() => setDel(null)} onConfirm={() => act(() => api.deleteSignature(del.id), t("sig.deleted"))} />
      )}
    </Page>
  );
}

function SigForm({ onAdd }) {
  const { t } = useI18n();
  const blank = { name: "", type: "header_present", pattern: "", severity: "medium", title: "", fix: "" };
  const [f, setF] = useState(blank);
  const [busy, setBusy] = useState(false);
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    if (await onAdd({ ...f, name: f.name.trim(), pattern: f.pattern.trim(), enabled: true })) setF(blank);
    setBusy(false);
  };

  return (
    <form className="form-grid side-form" onSubmit={submit}>
      <Field label={t("sig.name")} className="span-2">
        <input value={f.name} onChange={set("name")} required maxLength={120} placeholder={t("sig.namePh")} />
      </Field>
      <Field label={t("sig.type")} hint={t(`sigt.${f.type}`)} className="span-2">
        <select value={f.type} onChange={set("type")}>
          {TYPES.map((k) => <option key={k} value={k}>{k}</option>)}
        </select>
      </Field>
      <Field label={t("sig.pattern")} className="span-2">
        <input className="mono" value={f.pattern} onChange={set("pattern")} required spellCheck={false} placeholder={t(`sigp.${f.type}`)} />
      </Field>
      <Field label={t("f.sev")} className="span-2">
        <select value={f.severity} onChange={set("severity")}>
          {SEVS.map((s) => <option key={s} value={s}>{t(`sev.${s}`)}</option>)}
        </select>
      </Field>
      <Field label={t("sig.findingTitle")} hint={t("ui.optional")} className="span-2">
        <input value={f.title} onChange={set("title")} maxLength={200} />
      </Field>
      <Field label={t("f.fix")} hint={t("ui.optional")} className="span-2">
        <input value={f.fix} onChange={set("fix")} maxLength={1000} />
      </Field>
      <div className="span-2 form-actions">
        <button type="submit" className="btn btn-primary" disabled={busy}>{t("sig.add")}</button>
      </div>
    </form>
  );
}

function TypeList() {
  const { t } = useI18n();
  return (
    <dl className="type-list">
      {TYPES.map((k) => (
        <div key={k}><dt className="mono">{k}</dt><dd>{t(`sigt.${k}`)}</dd></div>
      ))}
    </dl>
  );
}
