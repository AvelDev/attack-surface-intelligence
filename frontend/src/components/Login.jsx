import { useState } from "react";
import { Sun, Moon } from "lucide-react";
import { api } from "../api.js";
import { useI18n } from "../i18n.jsx";

export default function Login({ onLogin, theme, onTheme }) {
  const { t, lang, setLang } = useI18n();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      onLogin(await api.login(username, password));
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  }

  return (
    <main className="login">
      <div className="login-tools">
        <div className="seg" role="group" aria-label={t("top.lang")}>
          {["pl", "en"].map((l) => (
            <button key={l} type="button" aria-pressed={lang === l} onClick={() => setLang(l)}>{l.toUpperCase()}</button>
          ))}
        </div>
        <button type="button" className="icon-btn" onClick={onTheme} aria-label={t("top.theme")}>
          {theme === "dark" ? <Sun size={16} aria-hidden="true" /> : <Moon size={16} aria-hidden="true" />}
        </button>
      </div>
      <form className="mod login-card" onSubmit={submit} aria-labelledby="login-h">
        <span className="mod-tag" aria-hidden="true">ASI</span>
        <div className="brand brand-lg" aria-hidden="true">A<span>S</span>I</div>
        <h1 className="mod-title" id="login-h">{t("login.title")}</h1>
        <label className="field">
          <span>{t("login.user")}</span>
          <input autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required autoFocus />
        </label>
        <label className="field">
          <span>{t("login.pass")}</span>
          <input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </label>
        {error && <p className="form-error" role="alert">{error}</p>}
        <button className="btn btn-primary" type="submit" disabled={busy}>{busy ? t("login.busy") : t("login.submit")}</button>
        <p className="login-hint">{t("login.hint")}</p>
      </form>
    </main>
  );
}
