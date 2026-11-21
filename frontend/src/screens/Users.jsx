import { useState } from "react";
import { Trash2 } from "lucide-react";
import { api, can, ROLES } from "../api.js";
import { useI18n } from "../i18n.jsx";
import Frame from "../components/Frame.jsx";
import Page from "../components/Page.jsx";
import { Confirm, Empty, Field, LoadState, useResource, useToast } from "../components/ui.jsx";

/** Konta i role RBAC; tylko administrator. */
export default function Users({ user, shell, onAuthLost }) {
  const { t, n, date } = useI18n();
  const { toast, flash, clear } = useToast();
  const isAdmin = can(user, "admin");
  const res = useResource(() => (isAdmin ? api.users() : Promise.resolve([])), onAuthLost, [isAdmin]);
  const [del, setDel] = useState(null);
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

  if (!isAdmin) {
    return (
      <Page shell={shell} title={t("nav.users")} toast={toast} onToastClose={clear} className="single">
        <section className="mod"><Empty title={t("u.denied")}><p className="quiet">{t("u.deniedHint")}</p></Empty></section>
      </Page>
    );
  }

  return (
    <Page shell={shell} title={t("nav.users")} refreshing={res.loading} onRefresh={res.load}
          toast={toast} onToastClose={clear} className="split">
      <Frame tag="A" id="u-list" className="split-main" title={t("u.title")} meta={res.data ? n(rows.length) : null}>
        {!res.data ? <LoadState error={res.error} onRetry={res.load} /> : (
          <div className="t-scroll">
            <table className="d-table">
              <thead>
                <tr>
                  <th scope="col">{t("login.user")}</th>
                  <th scope="col">{t("u.role")}</th>
                  <th scope="col">{t("u.created")}</th>
                  <th scope="col"><span className="sr-only">{t("ui.delete")}</span></th>
                </tr>
              </thead>
              <tbody>
                {rows.map((u) => {
                  const self = u.username === user.username;
                  return (
                    <tr key={u.id} className={self ? "is-focused" : ""}>
                      <th scope="row" className="nowrap">
                        {u.username}{self && <span className="chip u-you">{t("u.you")}</span>}
                      </th>
                      <td>
                        <span className="u-role"><RolePips role={u.role} />{t(`role.${u.role}`)}</span>
                      </td>
                      <td className="mono nowrap">{date(u.created)}</td>
                      <td className="d-act">
                        {!self && (
                          <button type="button" className="icon-btn btn-del" onClick={() => setDel(u)} aria-label={t("u.deleteOf", { name: u.username })} title={t("ui.delete")}>
                            <Trash2 size={14} aria-hidden="true" />
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Frame>
      <Frame tag="B" id="u-new" className="split-side" title={t("u.new")}>
        <UserForm onAdd={(body) => act(() => api.addUser(body), t("u.added", { name: body.username }))} />
      </Frame>
      {del && (
        <Confirm title={t("u.deleteTitle")} body={t("u.deleteBody", { name: del.username })} confirmLabel={t("ui.delete")}
                 onClose={() => setDel(null)} onConfirm={() => act(() => api.deleteUser(del.id), t("u.deleted"))} />
      )}
    </Page>
  );
}

/** Uprawnienia rosną z rangą: liczba wypełnionych segmentów = poziom roli. */
function RolePips({ role }) {
  const rank = ROLES.indexOf(role);
  return (
    <span className="pips" aria-hidden="true">
      {ROLES.map((r, i) => <i key={r} className={i <= rank ? "on" : ""} />)}
    </span>
  );
}

function UserForm({ onAdd }) {
  const { t } = useI18n();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("read");
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    if (await onAdd({ username: username.trim(), password, role })) { setUsername(""); setPassword(""); setRole("read"); }
    setBusy(false);
  };

  return (
    <form className="form-grid side-form" onSubmit={submit}>
      <Field label={t("login.user")} className="span-2">
        <input value={username} onChange={(e) => setUsername(e.target.value)} required maxLength={64} autoComplete="off" />
      </Field>
      <Field label={t("login.pass")} hint={t("u.passHint")} className="span-2">
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={8} autoComplete="new-password" />
      </Field>
      <fieldset className="span-2 fs roles">
        <legend>{t("u.role")}</legend>
        {ROLES.map((r) => (
          <label key={r} className={`role-opt${role === r ? " is-on" : ""}`}>
            <input type="radio" name="role" value={r} checked={role === r} onChange={() => setRole(r)} />
            <span className="role-name"><RolePips role={r} />{t(`role.${r}`)}</span>
            <small>{t(`u.desc.${r}`)}</small>
          </label>
        ))}
      </fieldset>
      <div className="span-2 form-actions">
        <button type="submit" className="btn btn-primary" disabled={busy}>{t("u.add")}</button>
      </div>
    </form>
  );
}
