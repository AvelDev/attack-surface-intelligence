import { useEffect, useState } from "react";
import { api, can } from "../api.js";
import { useI18n } from "../i18n.jsx";
import Frame from "../components/Frame.jsx";
import Page from "../components/Page.jsx";
import { Field, LoadState, useResource, useToast } from "../components/ui.jsx";

const SCAN_TOOLS = ["nmap", "subfinder", "dnsx", "naabu", "httpx", "nuclei"];

/** Integracje: konfiguracja DefectDojo (tylko admin) i stan narzędzi w obrazie. */
export default function Settings({ user, shell, onAuthLost }) {
  const { t } = useI18n();
  const { toast, flash, clear } = useToast();
  const settings = useResource(api.settings, onAuthLost, []);
  const tools = useResource(api.tools, onAuthLost, []);
  const isAdmin = can(user, "admin");

  const reload = () => { settings.load(); tools.load(); };

  return (
    <Page shell={shell} title={t("nav.settings")} refreshing={settings.loading || tools.loading} onRefresh={reload}
          toast={toast} onToastClose={clear} className="split split-even">
      <Frame tag="A" id="dojo" className="split-main" title="DefectDojo"
             meta={settings.data ? (settings.data.defectdojo_configured ? t("set.configured") : t("set.notConfigured")) : null}>
        {!settings.data ? <LoadState error={settings.error} onRetry={settings.load} /> : (
          <DojoForm key={settings.data.defectdojo_url} s={settings.data} isAdmin={isAdmin} onAuthLost={onAuthLost} flash={flash} onSaved={reload} />
        )}
      </Frame>
      <Frame tag="B" id="tools" className="split-side tools-mod" title={t("set.tools")}>
        {!tools.data ? <LoadState error={tools.error} onRetry={tools.load} /> : <ToolTable tools={tools.data} />}
      </Frame>
    </Page>
  );
}

function DojoForm({ s, isAdmin, onAuthLost, flash, onSaved }) {
  const { t } = useI18n();
  const [url, setUrl] = useState(s.defectdojo_url || "");
  const [key, setKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => setUrl(s.defectdojo_url || ""), [s.defectdojo_url]);

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      await api.saveDojo(url.trim(), key.trim());
      setKey("");
      flash(t("set.saved"), "ok");
      onSaved();
    } catch (err) {
      onAuthLost(err);
      setError(err.message);
    }
    setBusy(false);
  };

  return (
    <form className="form-grid dojo-form" onSubmit={submit}>
      <p className={`set-status span-2 ${s.defectdojo_configured ? "is-on" : ""}`}>
        <i aria-hidden="true" />
        {s.defectdojo_configured ? t("set.statusOn", { url: s.defectdojo_url }) : t("set.statusOff")}
      </p>
      <Field label={t("set.url")} className="span-2">
        <input className="mono" type="url" value={url} onChange={(e) => setUrl(e.target.value)} disabled={!isAdmin}
               placeholder="https://defectdojo.example.org" required spellCheck={false} />
      </Field>
      <Field label={t("set.key")} hint={s.defectdojo_configured ? t("set.keyKeep") : null} className="span-2">
        <input className="mono" type="password" value={key} onChange={(e) => setKey(e.target.value)} disabled={!isAdmin}
               autoComplete="off" required placeholder={t("set.keyPh")} />
      </Field>
      <p className="field-hint span-2">{t("set.how")}</p>
      {error && <p className="form-error span-2" role="alert">{error}</p>}
      {isAdmin ? (
        <div className="span-2 form-actions"><button type="submit" className="btn btn-primary" disabled={busy}>{t("set.save")}</button></div>
      ) : (
        <p className="q-ro span-2">{t("set.adminOnly")}</p>
      )}
    </form>
  );
}

function ToolTable({ tools }) {
  const { t } = useI18n();
  const scan = SCAN_TOOLS.filter((k) => tools[k]);
  const ext = Object.keys(tools).filter((k) => !SCAN_TOOLS.includes(k));
  const row = (k) => {
    const v = tools[k];
    return (
      <tr key={k}>
        <th scope="row" className="mono">{k}</th>
        <td className="nowrap">
          <span className={`tool-st ${v.installed ? "is-on" : ""}`}>
            <i aria-hidden="true" />
            {ext.includes(k) ? (v.installed ? t("tools.reachable") : t("tools.off")) : v.installed ? t("tools.installed") : t("tools.fallback")}
          </span>
          {k === "naabu" && v.installed && <small className="d-sub">{v.syn ? t("tools.syn") : t("tools.connect")}</small>}
        </td>
        <td className="mono quiet f-asset">{v.path || "—"}</td>
      </tr>
    );
  };
  return (
    <div className="t-scroll">
      <table className="d-table">
        <thead><tr><th scope="col">{t("set.tool")}</th><th scope="col">{t("d.state")}</th><th scope="col">{t("set.path")}</th></tr></thead>
        <tbody>
          {scan.map(row)}
          <tr className="t-group"><th scope="rowgroup" colSpan={3}>{t("set.external")}</th></tr>
          {ext.map(row)}
        </tbody>
      </table>
      <p className="field-hint side-note">{t("tools.note")}</p>
    </div>
  );
}
