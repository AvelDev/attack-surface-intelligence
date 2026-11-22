import { useEffect, useMemo, useRef, useState } from "react";
import { Check, ShieldCheck, Ban, RotateCcw, Upload, X } from "lucide-react";
import { useI18n } from "../i18n.jsx";
import { can } from "../api.js";
import Frame from "./Frame.jsx";
import KindIcon from "./KindIcon.jsx";

const SHOW = 60;

function hostOf(item) {
  const v = item.value || "";
  const m = v.match(/^[a-z]+:\/\/([^/:]+)(?::(\d+))?/i);
  if (m) return { host: m[1], port: m[2] || (v.startsWith("https") ? "443" : "80") };
  const p = v.lastIndexOf(":");
  if (p > 0 && /^\d+$/.test(v.slice(p + 1))) return { host: v.slice(0, p), port: v.slice(p + 1) };
  return { host: v, port: null };
}

function matches(item, f) {
  if (!f) return true;
  if (f.type === "kind") return f.value === "critical" ? item.severity === "critical" : item.kind === f.value;
  const { host, port } = hostOf(item);
  if (f.type === "host") return host === f.value;
  if (f.type === "block") {
    const base = f.value.replace(/\.0\/24$/, ".");
    return host.startsWith(base);
  }
  if (f.type === "asset") return item.asset === f.value || `${host}:${port}` === f.port;
  return true;
}

export default function Triage({ data, user, filter, onFilter, onTriage, onExport, canExport }) {
  const { t, n } = useI18n();
  const [mode, setMode] = useState("open");
  const [selected, setSelected] = useState(() => new Set());
  const [cursor, setCursor] = useState(0);
  const [busy, setBusy] = useState(false);
  const listRef = useRef(null);
  const canTriage = can(user, "read_modify");

  const items = useMemo(
    () => data.queue.filter((q) => (mode === "all" || q.triage === "open") && matches(q, filter)),
    [data.queue, mode, filter]
  );
  const shown = items.slice(0, SHOW);

  useEffect(() => {
    setSelected((s) => new Set([...s].filter((id) => data.queue.some((q) => q.id === id))));
  }, [data.queue]);
  useEffect(() => { setCursor((c) => Math.min(c, Math.max(0, shown.length - 1))); }, [shown.length]);

  const focusRow = (i) => {
    setCursor(i);
    listRef.current?.querySelectorAll(".q-row")[i]?.focus();
  };

  const decide = async (item, status) => {
    if (!canTriage) return;
    await onTriage(item, status);
  };

  const toggle = (id) => setSelected((s) => {
    const next = new Set(s);
    next.has(id) ? next.delete(id) : next.add(id);
    return next;
  });

  const doExport = async () => {
    const chosen = data.queue.filter((q) => selected.has(q.id));
    if (!chosen.length) return;
    setBusy(true);
    const r = await onExport(chosen);
    setBusy(false);
    if (r) setSelected(new Set());
  };

  const onKeyDown = (e) => {
    if (!shown.length || e.target.closest("button.q-act, input")) return;
    // wiersz bierzemy z elementu zdarzenia, nie ze stanu: stan kursora może być o render spóźniony
    const rowEl = e.target.closest(".q-row");
    const idx = rowEl ? [...listRef.current.querySelectorAll(".q-row")].indexOf(rowEl) : cursor;
    const item = shown[idx];
    if (!item) return;
    const k = e.key;
    if (k === "ArrowDown" || k === "j") { e.preventDefault(); focusRow(Math.min(shown.length - 1, idx + 1)); }
    else if (k === "ArrowUp" || k === "k") { e.preventDefault(); focusRow(Math.max(0, idx - 1)); }
    else if (k === "Home") { e.preventDefault(); focusRow(0); }
    else if (k === "End") { e.preventDefault(); focusRow(shown.length - 1); }
    else if ((k === "x" || k === " ") && canExport) { e.preventDefault(); toggle(item.id); }
    else if (k === "1") decide(item, "ok");
    else if (k === "2") decide(item, "accepted");
    else if (k === "3") decide(item, "false_positive");
    else if (k === "0") decide(item, "open");
    else if (k === "e" && canExport) doExport();
  };

  return (
    <Frame
      tag="C"
      id="mod-c"
      className="mod-c"
      title={t("c.title")}
      meta={n(items.length)}
      actions={
        <div className="seg seg-sm" role="group" aria-label={t("c.filter")}>
          <button type="button" aria-pressed={mode === "open"} onClick={() => setMode("open")}>{t("c.open")}</button>
          <button type="button" aria-pressed={mode === "all"} onClick={() => setMode("all")}>{t("c.all")}</button>
        </div>
      }
    >
      {filter && (
        <div className="q-filter">
          <span>{t("c.filter")}: <b className="mono">{filter.label}</b></span>
          <button type="button" className="icon-btn sm" onClick={() => onFilter(null)} aria-label={t("c.clear")} title={t("c.clear")}>
            <X size={14} aria-hidden="true" />
          </button>
        </div>
      )}
      {!canTriage && <p className="q-ro">{t("c.readOnly")}</p>}
      {shown.length === 0 ? (
        <p className="q-empty">{filter ? t("c.emptyFiltered") : t("c.empty")}</p>
      ) : (
        <ul className="q-list" ref={listRef} onKeyDown={onKeyDown} aria-label={t("c.title")}>
          {shown.map((q, i) => (
            <QueueRow
              key={q.id}
              q={q}
              active={i === cursor}
              selected={selected.has(q.id)}
              canTriage={canTriage}
              canExport={canExport}
              onFocus={() => setCursor(i)}
              onToggle={() => toggle(q.id)}
              onDecide={(s) => decide(q, s)}
            />
          ))}
          {items.length > SHOW && <li className="q-more">{t("c.more", { shown: SHOW, total: n(items.length) })}</li>}
        </ul>
      )}
      {canExport && (
        <footer className="q-foot">
          <span className="mono">{t("c.selected", { n: selected.size })}</span>
          <span className="q-keys" aria-hidden="true"><kbd>1</kbd><kbd>2</kbd><kbd>3</kbd> {t("c.keysDecide")} · <kbd>X</kbd><kbd>E</kbd> {t("c.keysExport")}</span>
          <button type="button" className="btn" disabled={!selected.size || busy} onClick={doExport}>
            <Upload size={14} aria-hidden="true" /> {busy ? t("c.exporting") : t("c.export")}
          </button>
        </footer>
      )}
    </Frame>
  );
}

function QueueRow({ q, active, selected, canTriage, canExport, onFocus, onToggle, onDecide }) {
  const { t, tf } = useI18n();
  const [k, nAll] = q.confidence || [0, 0];
  const closed = q.triage !== "open";
  const kindLabel = q.kind === "finding" ? t(`sev.${q.severity}`) : t(`k.${q.kind}`);
  const title = tf(q.title);
  return (
    <li
      className={`q-row${closed ? " is-closed" : ""}${selected ? " is-selected" : ""} sev-${q.severity}`}
      tabIndex={active ? 0 : -1}
      onFocus={onFocus}
      aria-label={`${kindLabel}: ${q.value}. ${title}`}
    >
      {canExport && (
        <input
          type="checkbox"
          className="q-check"
          checked={selected}
          onChange={onToggle}
          aria-label={t("c.select")}
          tabIndex={-1}
        />
      )}
      <span className="q-kind" title={kindLabel}>
        <KindIcon kind={q.kind} severity={q.severity} />
      </span>
      <div className="q-body">
        <span className="q-line1">
          <span className="q-value mono">{q.value}</span>
          {nAll > 1 && (
            <span className="conf" title={t("c.confidence", { k, n: nAll })}>
              <span className="pips" aria-hidden="true">
                {Array.from({ length: nAll }, (_, i) => <i key={i} className={i < k ? "on" : ""} />)}
              </span>
              <span className="mono">{k}/{nAll}</span>
              <span className="sr-only">{t("c.confidence", { k, n: nAll })}</span>
            </span>
          )}
        </span>
        <span className="q-line2">
          <b className="q-kind-label">{kindLabel}</b>
          {q.tags.map((tg) => <span key={tg} className="chip">{t(`tag.${tg}`)}</span>)}
          {closed && <span className="q-status">{t("c.by", { status: t(`st.${q.triage}`), user: q.triage_by })}</span>}
          <span className="q-title" title={title}>{title}</span>
        </span>
      </div>
      {canTriage && (
        <div className="q-acts">
          {closed ? (
            <button type="button" className="q-act" onClick={() => onDecide("open")} title={t("c.reopen")} aria-label={t("c.reopen")}>
              <RotateCcw size={15} aria-hidden="true" />
            </button>
          ) : (
            <>
              <button type="button" className="q-act" onClick={() => onDecide("ok")} title={`${t("c.ok")} (1)`} aria-label={t("c.ok")}>
                <Check size={15} aria-hidden="true" />
              </button>
              <button type="button" className="q-act" onClick={() => onDecide("accepted")} title={`${t("c.accept")} (2)`} aria-label={t("c.accept")}>
                <ShieldCheck size={15} aria-hidden="true" />
              </button>
              <button type="button" className="q-act" onClick={() => onDecide("false_positive")} title={`${t("c.fp")} (3)`} aria-label={t("c.fp")}>
                <Ban size={15} aria-hidden="true" />
              </button>
            </>
          )}
        </div>
      )}
    </li>
  );
}
