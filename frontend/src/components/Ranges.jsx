import { useState } from "react";
import { Play, Pause, Pencil, Crosshair } from "lucide-react";
import { useI18n } from "../i18n.jsx";
import { can } from "../api.js";
import Frame from "./Frame.jsx";
import KindIcon from "./KindIcon.jsx";

export default function Ranges({ data, user, focused, onFocus, onRun, onStop, onNote }) {
  const { t, n } = useI18n();
  const canRun = can(user, "add_remove_modify");
  const canNote = can(user, "read_modify");
  return (
    <Frame tag="D" id="mod-d" className="mod-d" title={t("d.title")} meta={n(data.ranges.length)}>
      <div className="d-scroll">
        <table className="d-table">
          <thead>
            <tr>
              <th scope="col">{t("d.range")}</th>
              <th scope="col" className="num">{t("d.hosts")}</th>
              <th scope="col" className="num">{t("d.services")}</th>
              <th scope="col">{t("d.changes")}</th>
              <th scope="col">{t("d.state")}</th>
              <th scope="col">{t("d.window")}</th>
              <th scope="col">{t("d.lastChange")}</th>
              <th scope="col">{t("d.firstSeen")}</th>
              {canRun && <th scope="col"><span className="sr-only">{t("d.action")}</span></th>}
            </tr>
          </thead>
          <tbody>
            {data.ranges.map((r) => (
              <Row key={r.id} r={r} focused={focused === r.id} onFocus={onFocus} canRun={canRun} canNote={canNote}
                   onRun={onRun} onStop={onStop} onNote={onNote} />
            ))}
          </tbody>
        </table>
      </div>
    </Frame>
  );
}

function Row({ r, focused, onFocus, canRun, canNote, onRun, onStop, onNote }) {
  const { t, n, ago, day } = useI18n();
  const [editing, setEditing] = useState(false);
  const [note, setNote] = useState(r.note);
  const [pending, setPending] = useState(false);
  const st = r.state;
  const running = st.status === "running" || st.status === "queued";
  const pct = st.hosts_total ? Math.round((100 * st.hosts_done) / st.hosts_total) : 0;
  const c = r.counts;

  const saveNote = async (e) => {
    e.preventDefault();
    await onNote(r, note);
    setEditing(false);
  };

  return (
    <tr className={focused ? "is-focused" : ""}>
      <th scope="row" className="d-name">
        <button type="button" className="link mono" onClick={() => onFocus(focused ? null : r.id)} title={t("d.focus")}>
          {focused && <Crosshair size={13} aria-hidden="true" />} {r.name}
        </button>
        {editing ? (
          <form className="d-note-form" onSubmit={saveNote}>
            <input value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} placeholder={t("d.notePlaceholder")} autoFocus
                   onKeyDown={(e) => e.key === "Escape" && (setNote(r.note), setEditing(false))} aria-label={t("d.notePlaceholder")} />
            <button type="submit" className="btn btn-sm">{t("d.noteSave")}</button>
          </form>
        ) : (
          <span className="d-note">
            {r.note || (canNote ? <span className="quiet">{t("d.notePlaceholder")}</span> : null)}
            {canNote && (
              <button type="button" className="icon-btn sm" onClick={() => { setNote(r.note); setEditing(true); }} aria-label={t("d.noteEdit")} title={t("d.noteEdit")}>
                <Pencil size={12} aria-hidden="true" />
              </button>
            )}
          </span>
        )}
      </th>
      <td className="num mono">{n(r.hosts_alive)}</td>
      <td className="num mono">{n(r.services)}</td>
      <td>
        <span className="d-changes">
          {["new", "removed", "changed", "flapping"].map((k) =>
            c[k] ? (
              <span key={k} className="d-ch" title={t(`k.${k}`)}>
                <KindIcon kind={k} size={13} /><span className="mono">{n(c[k])}</span>
                <span className="sr-only">{t(`k.${k}`)}</span>
              </span>
            ) : null
          )}
          {c.critical ? (
            <span className="d-ch" title={t("k.critical")}>
              <KindIcon kind="critical" size={13} /><span className="mono crit">{n(c.critical)}</span>
              <span className="sr-only">{t("k.critical")}</span>
            </span>
          ) : null}
          {!(c.new || c.removed || c.changed || c.flapping || c.critical) && <span className="quiet">—</span>}
        </span>
      </td>
      <td>
        <span className={`d-state st-${st.status}`}>
          <i aria-hidden="true" />
          {st.status === "running" ? t("state.running", { pct }) : t(`state.${st.status}`)}
        </span>
        {r.schedule?.enabled && <small className="d-sub">{t("d.next", { when: day(r.schedule.next_run) })}</small>}
      </td>
      <td><Budget r={r} /></td>
      <td>{ago(r.last_change)}</td>
      <td className="mono">{day(r.first_seen)}</td>
      {canRun && (
        <td className="d-act">
          {running ? (
            <button type="button" className="btn btn-sm btn-danger" disabled={pending}
                    onClick={async () => { setPending(true); await onStop(r); setPending(false); }} title={t("state.stopHint")}>
              <Pause size={13} aria-hidden="true" /> {pending ? t("d.stopping") : t("d.stop")}
            </button>
          ) : (
            <button type="button" className="btn btn-sm" disabled={pending}
                    onClick={async () => { setPending(true); await onRun(r); setPending(false); }}>
              <Play size={13} aria-hidden="true" /> {t("d.run")}
            </button>
          )}
        </td>
      )}
    </tr>
  );
}

/** Okno skanu jako stały budżet czasu: ile zużył ostatni/bieżący przebieg, przekroczenie widać. */
function Budget({ r }) {
  const { t, dur } = useI18n();
  const used = r.state.elapsed || 0;
  if (!r.window_mins) return <span className="quiet mono">{dur(used)} · {t("d.noWindow")}</span>;
  const total = r.window_mins * 60;
  const ratio = used / total;
  const over = ratio > 1 || r.state.status === "paused_window";
  return (
    <div className={`budget${over ? " is-over" : ""}`}>
      <div className="budget-bar" role="meter" aria-valuemin={0} aria-valuemax={total} aria-valuenow={Math.round(Math.min(used, total))}
           aria-label={t("d.window")}>
        <i style={{ width: `${Math.min(100, ratio * 100)}%` }} />
      </div>
      <span className="mono budget-txt">
        {over && ratio > 1 ? t("d.windowOver", { d: dur(used - total) }) : t("d.windowOf", { used: dur(used), total: dur(total) })}
      </span>
    </div>
  );
}
