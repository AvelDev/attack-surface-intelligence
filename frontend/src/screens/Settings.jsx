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
      <div className="split-main settings-integrations">
        <Frame tag="A" id="dojo" title="DefectDojo"
               meta={settings.data ? (settings.data.defectdojo_configured ? t("set.configured") : t("set.notConfigured")) : null}>
          {!settings.data ? <LoadState error={settings.error} onRetry={settings.load} /> : (
            <DojoForm key={settings.data.defectdojo_url} s={settings.data} isAdmin={isAdmin} onAuthLost={onAuthLost} flash={flash} onSaved={reload} />
          )}
        </Frame>
        <Frame tag="B" id="gvm" title="OpenVAS / GVM"
               meta={settings.data ? (settings.data.gvm_configured ? t("set.configured") : t("set.notConfigured")) : null}>
          {!settings.data ? <LoadState error={settings.error} onRetry={settings.load} /> : (
            <GvmForm key={settings.data.gvm_host} s={settings.data} isAdmin={isAdmin} onAuthLost={onAuthLost} flash={flash} onSaved={reload} />
          )}
        </Frame>
      </div>
      <Frame tag="C" id="tools" className="split-side tools-mod" title={t("set.tools")}>
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

function GvmForm({ s, isAdmin, onAuthLost, flash, onSaved }) {
  const { t } = useI18n();
  const [host, setHost] = useState(s.gvm_host || "");
  const [port, setPort] = useState(s.gvm_port || 9390);
  const [username, setUsername] = useState(s.gvm_username || "admin");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    setHost(s.gvm_host || "");
    setPort(s.gvm_port || 9390);
    setUsername(s.gvm_username || "admin");
  }, [s.gvm_host, s.gvm_port, s.gvm_username]);

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      await api.saveGvm(host.trim(), +port, username.trim(), password.trim());
      setPassword("");
      flash(t("set.gvmSaved"), "ok");
      onSaved();
    } catch (err) {
      onAuthLost(err);
      setError(err.message);
    }
    setBusy(false);
  };

  return (
    <form className="form-grid gvm-form" onSubmit={submit}>
      <p className={`set-status span-2 ${s.gvm_configured ? "is-on" : ""}`}>
        <i aria-hidden="true" />
        {s.gvm_configured ? t("set.gvmStatusOn", { host: s.gvm_host }) : t("set.gvmStatusOff")}
      </p>
      <Field label={t("set.gvmHost")}>
        <input className="mono" value={host} onChange={(e) => setHost(e.target.value)} disabled={!isAdmin}
               placeholder="10.0.0.5" required spellCheck={false} />
      </Field>
      <Field label={t("set.gvmPort")}>
        <input className="mono" type="number" min={1} max={65535} value={port}
               onChange={(e) => setPort(e.target.value)} disabled={!isAdmin} required />
      </Field>
      <Field label={t("set.gvmUsername")}>
        <input className="mono" value={username} onChange={(e) => setUsername(e.target.value)} disabled={!isAdmin}
               spellCheck={false} />
      </Field>
      <Field label={t("set.gvmPassword")} hint={s.gvm_configured ? t("set.gvmPasswordKeep") : null}>
        <input className="mono" type="password" value={password} onChange={(e) => setPassword(e.target.value)}
               disabled={!isAdmin} autoComplete="off" required placeholder={t("set.gvmPasswordPh")} />
      </Field>
      <p className="field-hint span-2">{t("set.gvmHow")}</p>
      {error && <p className="form-error span-2" role="alert">{error}</p>}
      {isAdmin ? (
        <div className="span-2 form-actions"><button type="submit" className="btn btn-primary" disabled={busy}>{t("set.save")}</button></div>
      ) : (
        <p className="q-ro span-2">{t("set.gvmAdminOnly")}</p>
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
