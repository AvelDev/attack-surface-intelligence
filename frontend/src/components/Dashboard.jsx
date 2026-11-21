import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, can } from "../api.js";
import { useI18n } from "../i18n.jsx";
import TopBar from "./TopBar.jsx";
import Changes from "./Changes.jsx";
import AddressMap from "./AddressMap.jsx";
import Triage from "./Triage.jsx";
import Ranges from "./Ranges.jsx";
import Ticker from "./Ticker.jsx";
import Shortcuts from "./Shortcuts.jsx";
import RangeBar from "./RangeBar.jsx";
import NewScan from "./NewScan.jsx";
import { useToast, ToastRegion } from "./ui.jsx";
import { go } from "../router.js";

const FAST = 5000;   // gdy jakiś skan trwa
const SLOW = 30000;

export default function Dashboard({ user, onAuthLost, shell }) {
  const { t } = useI18n();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [refreshing, setRefreshing] = useState(false);
  const [range, setRange] = useState(null);
  const [scan, setScan] = useState(null);       // przebieg wybrany suwakiem (null = najnowszy)
  const [filter, setFilter] = useState(null);   // {type:'kind'|'block'|'host', value, label}
  const [showKeys, setShowKeys] = useState(false);
  const { toast, flash, clear } = useToast();
  const [adding, setAdding] = useState(false);
  const [rangesAll, setRangesAll] = useState([]);
  const [historyAll, setHistoryAll] = useState([]); // tor suwaka dni zawsze z najnowszego stanu
  const timer = useRef(null);
  const reqId = useRef(0);

  const load = useCallback(async () => {
    const id = ++reqId.current;
    setRefreshing(true);
    try {
      const d = await api.dashboard(range, scan);
      if (id !== reqId.current) return;
      setData(d);
      setError(null);
      if (!range) setRangesAll(d.ranges.map((r) => ({ id: r.id, name: r.name })));
      if (!range && !scan) setHistoryAll(d.history);
    } catch (e) {
      if (id !== reqId.current) return;
      onAuthLost(e);
      setError(e.message);
    } finally {
      if (id === reqId.current) setRefreshing(false);
    }
  }, [range, scan, onAuthLost]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { document.title = t("app.title"); }, [t]);

  // polling: szybciej, gdy coś się skanuje; wstrzymany na ukrytej karcie
  useEffect(() => {
    clearTimeout(timer.current);
    const delay = data?.meta?.running ? FAST : SLOW;
    const tick = () => {
      if (document.visibilityState === "visible") load();
      timer.current = setTimeout(tick, delay);
    };
    timer.current = setTimeout(tick, delay);
    return () => clearTimeout(timer.current);
  }, [data, load]);

  const chooseRange = useCallback((r) => {
    setRange(r);
    setScan(null);
    setFilter(null);
  }, []);

  const act = useCallback(async (fn, okMsg) => {
    try {
      const r = await fn();
      if (okMsg) flash(typeof okMsg === "function" ? okMsg(r) : okMsg, "ok");
      await load();
      return r;
    } catch (e) {
      onAuthLost(e);
      flash(t("err.action", { msg: e.message }), "err");
      return null;
    }
  }, [flash, load, onAuthLost, t]);

  useEffect(() => {
    const onKey = (e) => {
      if (e.target.closest("input, textarea, select, [contenteditable]")) return;
      if (e.key === "?") { e.preventDefault(); setShowKeys((v) => !v); }
      else if (e.key === "r" && !e.metaKey && !e.ctrlKey) { e.preventDefault(); load(); }
      else if (e.key === "/") { e.preventDefault(); document.getElementById("range-select")?.focus(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [load]);

  const focused = useMemo(() => (range && data ? data.ranges.find((r) => r.id === range) : null), [range, data]);

  return (
    <>
      <TopBar shell={shell} refreshing={refreshing} onRefresh={load} onShortcuts={() => setShowKeys(true)}>
        <RangeBar ranges={rangesAll} range={range} onRange={chooseRange} lastPass={data?.meta?.last_pass} />
      </TopBar>
      <main id="main" className="dash" aria-busy={!data && !error}>
        {error && !data && (
          <div className="load-error" role="alert">
            <p>{t("err.load", { msg: error })}</p>
            <button type="button" className="btn" onClick={load}>{t("err.retry")}</button>
          </div>
        )}
        {error && data && <div className="stale" role="status">{t("err.load", { msg: error })}</div>}
        {!data && !error && <Skeleton />}
        {data && (
          <>
            <Changes data={data} focused={focused} filter={filter} onFilter={setFilter} />
            <AddressMap
              data={data}
              focused={focused}
              scan={scan}
              onScan={setScan}
              historyAll={historyAll}
              filter={filter}
              onFilter={setFilter}
              onAdd={can(user, "add_remove_modify") ? () => setAdding(true) : null}
            />
            <Triage
              data={data}
              user={user}
              filter={filter}
              onFilter={setFilter}
              onTriage={(item, status) => act(() => api.triage(item, status))}
              onExport={(items) => act(() => api.exportDojo(items), (r) => t("c.exported", { n: r.count }))}
              canExport={can(user, "add_remove_modify")}
            />
            <Ranges
              data={data}
              user={user}
              focused={range}
              onFocus={chooseRange}
              onRun={(r) => act(() => api.run(r.id))}
              onStop={(r) => act(() => api.stop(r.state.scan_id), t("state.stopHint"))}
              onNote={(r, note) => act(() => api.note(r.id, note))}
            />
          </>
        )}
      </main>
      <Ticker data={data} />
      {showKeys && <Shortcuts onClose={() => setShowKeys(false)} />}
      {adding && <NewScan onClose={() => setAdding(false)} onAuthLost={onAuthLost} flash={flash}
                          onStarted={(id) => go("scans", id)} />}
      <ToastRegion toast={toast} onClose={clear} />
    </>
  );
}

function Skeleton() {
  return (
    <>
      {["a", "b", "c", "d"].map((k) => (
        <div key={k} className={`mod skel skel-${k}`} aria-hidden="true">
          <span className="skel-line" />
          <span className="skel-line short" />
        </div>
      ))}
    </>
  );
}
