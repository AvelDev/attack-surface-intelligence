import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Plus, Search, FileText, Download, Upload, RotateCcw, Trash2, Pause } from "lucide-react";
import { api, can, isRunning, SEVS } from "../api.js";
import { useI18n } from "../i18n.jsx";
import { go, href } from "../router.js";
import Frame from "../components/Frame.jsx";
import Page from "../components/Page.jsx";
import NewScan from "../components/NewScan.jsx";
import KindIcon from "../components/KindIcon.jsx";
import { FindingsTable, FindingDialog } from "../components/Findings.jsx";
import { Confirm, Empty, LoadState, ScanState, Sev, useResource, useToast } from "../components/ui.jsx";

const STEPS = ["sub", "dns", "ports", "http", "vuln"];

function stepOf(scan) {
  if (scan.status === "done") return STEPS.length;
  const s = (scan.stage || "").toLowerCase();
  if (s.includes("subdomen")) return 0;
  if (s.includes("dns")) return 1;
  if (s.includes("port")) return 2;
  if (s.includes("http")) return 3;
  if (s.includes("podatno") || s.includes("nuclei")) return 4;
  return -1;
}

const pctOf = (s) => (s.hosts_total ? Math.round((100 * (s.hosts_done || 0)) / s.hosts_total) : null);

export default function Scans({ user, shell, onAuthLost, scanId }) {
  const { t, n } = useI18n();
  const { toast, flash, clear } = useToast();
  const [adding, setAdding] = useState(null);
  const [q, setQ] = useState("");
  const list = useResource(api.scans, onAuthLost, []);
  const scans = list.data || [];
  const anyRunning = scans.some((s) => isRunning(s.status));
  const canAdd = can(user, "add_remove_modify");

  useEffect(() => {
    const h = setInterval(() => document.visibilityState === "visible" && list.load(), anyRunning ? 4000 : 30000);
    return () => clearInterval(h);
  }, [anyRunning, list.load]);

  // bez wybranego skanu: pokaż najnowszy, żeby ekran nigdy nie był pusty
  const selected = scanId ? +scanId : scans[0]?.id ?? null;

  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return needle ? scans.filter((s) => `#${s.id} ${s.target} ${s.status}`.toLowerCase().includes(needle)) : scans;
  }, [scans, q]);

  return (
    <Page shell={shell} title={t("nav.ranges")} sub={t("s.sub", { n: n(scans.length) })}
          refreshing={list.loading} onRefresh={list.load} toast={toast} onToastClose={clear} className="scans">
      <Frame tag="A" id="s-list" className="s-list" title={t("s.list")} meta={n(scans.length)}
             actions={canAdd && (
               <button type="button" className="btn btn-primary btn-sm" onClick={() => setAdding({})}>
                 <Plus size={13} aria-hidden="true" /> {t("s.new")}
               </button>
             )}>
        <label className="search">
          <Search size={14} aria-hidden="true" />
          <span className="sr-only">{t("s.search")}</span>
          <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder={t("s.search")} />
        </label>
        {!list.data ? <LoadState error={list.error} onRetry={list.load} /> : (
          <ul className="s-items">
            {shown.map((s) => <ScanItem key={s.id} s={s} current={s.id === selected} />)}
            {!shown.length && <li className="q-empty">{scans.length ? t("c.emptyFiltered") : t("s.none")}</li>}
          </ul>
        )}
      </Frame>
      {list.data && !scans.length ? (
        <section className="mod s-detail" aria-label={t("s.detail")}>
          <Empty title={t("b.empty")}>
            <p className="quiet">{t("b.emptyHint")}</p>
            {canAdd && <button type="button" className="btn btn-primary" onClick={() => setAdding({})}>{t("b.emptyCta")}</button>}
          </Empty>
        </section>
      ) : selected ? (
        <ScanDetail key={selected} id={selected} user={user} onAuthLost={onAuthLost} flash={flash}
                    onChanged={list.load} onRepeat={setAdding} />
      ) : (
        <div className="mod s-detail skel" aria-hidden="true"><span className="skel-line" /><span className="skel-line short" /></div>
      )}
      {adding && (
        <NewScan initial={adding} onClose={() => setAdding(null)} onAuthLost={onAuthLost} flash={flash}
                 onStarted={(id) => { list.load(); go("scans", id); }} />
      )}
    </Page>
  );
}

function ScanItem({ s, current }) {
  const { t, n, ago } = useI18n();
  const pct = pctOf(s);
  return (
    <li>
      <a href={href("scans", s.id)} className={`s-item${current ? " is-current" : ""}`} aria-current={current ? "page" : undefined}>
        <span className="s-item-l1">
          <span className="mono quiet">#{s.id}</span>
          <span className="mono s-item-target" title={s.target}>{s.target}</span>
          <span className="mono s-score" title={t("s.score")}>{s.score ?? "—"}</span>
        </span>
        <span className="s-item-l2">
          <ScanState status={s.status} pct={pct} />
          <span>{t("s.findingsN", { n: n(s.findings) })}</span>
          <span className="s-item-when">{ago(s.created)}</span>
        </span>
      </a>
    </li>
  );
}

function ScanDetail({ id, user, onAuthLost, flash, onChanged, onRepeat }) {
  const { t, n, date, dur } = useI18n();
  const res = useResource(() => api.scan(id), onAuthLost, [id]);
  const [tab, setTab] = useState("findings");
  const [editing, setEditing] = useState(null);
  const [confirmDel, setConfirmDel] = useState(false);
  const [sending, setSending] = useState(false);
  const d = res.data;
  const running = d && isRunning(d.scan.status);

  useEffect(() => {
    if (!running) return;
    const h = setInterval(() => document.visibilityState === "visible" && res.load(), 2500);
    return () => clearInterval(h);
  }, [running, res.load]);

  // po zakończeniu skanu odśwież też listę (wynik, liczba ustaleń)
  const wasRunning = useRef(false);
  useEffect(() => {
    if (wasRunning.current && !running) onChanged();
    wasRunning.current = !!running;
  }, [running, onChanged]);

  const act = useCallback(async (fn, ok) => {
    try {
      const r = await fn();
      if (ok) flash(ok, "ok");
      return r;
    } catch (e) {
      onAuthLost(e);
      flash(t("err.action", { msg: e.message }), "err");
      return null;
    }
  }, [flash, onAuthLost, t]);

  if (!d) {
    return (
      <section className="mod s-detail" aria-busy="true" aria-label={t("s.detail")}>
        <LoadState error={res.error} onRetry={res.load} rows={6} />
      </section>
    );
  }

  const s = d.scan;
  const pct = pctOf(s);
  const step = stepOf(s);
  const opts = (() => { try { return JSON.parse(s.opts || "{}"); } catch (e) { return {}; } })();
  const canAdd = can(user, "add_remove_modify");

  const repeat = async () => {
    const targets = await act(() => api.scanTargets(s.id));
    if (targets) onRepeat({ targets: targets.join("\n"), rate: opts.rate_limit || 300, window: opts.time_window_mins || 0, nuclei: !!opts.nuclei, gvm: !!opts.gvm });
  };

  const tabs = [
    ["findings", t("s.tabFindings"), d.findings.length],
    ["assets", t("s.tabAssets"), d.assets.length],
    ["diff", t("s.tabDiff"), d.diff ? d.diff.new_assets.length + d.diff.removed_assets.length + d.diff.flapping_assets.length : null],
    ["log", t("s.tabLog"), null],
  ];

  return (
    <Frame tag="B" id="s-detail" className="s-detail" title={t("s.scanN", { id: s.id })}
           meta={<span className="mono">{s.target}</span>}
           actions={
             <div className="s-acts">
               <a className="btn btn-sm" href={`/api/scans/${s.id}/report`} target="_blank" rel="noopener"><FileText size={13} aria-hidden="true" /> {t("s.report")}</a>
               <a className="btn btn-sm" href={`/api/scans/${s.id}/export.json`}><Download size={13} aria-hidden="true" /> JSON</a>
               <a className="btn btn-sm" href={`/api/scans/${s.id}/export.csv`}><Download size={13} aria-hidden="true" /> CSV</a>
               {canAdd && (
                 <>
                   <button type="button" className="btn btn-sm" disabled={sending || !d.findings.length}
                           onClick={async () => { setSending(true); await act(() => api.scanToDojo(s.id), t("s.dojoOk")); setSending(false); }}>
                     <Upload size={13} aria-hidden="true" /> {sending ? t("c.exporting") : "DefectDojo"}
                   </button>
                   {running ? (
                     <button type="button" className="btn btn-sm btn-danger" title={t("state.stopHint")}
                             onClick={() => act(() => api.stop(s.id), t("state.stopHint")).then(res.load)}>
                       <Pause size={13} aria-hidden="true" /> {t("d.stop")}
                     </button>
                   ) : (
                     <>
                       <button type="button" className="btn btn-sm" onClick={repeat}><RotateCcw size={13} aria-hidden="true" /> {t("s.repeat")}</button>
                       <button type="button" className="icon-btn btn-del" onClick={() => setConfirmDel(true)} aria-label={t("s.delete")} title={t("s.delete")}>
                         <Trash2 size={15} aria-hidden="true" />
                       </button>
                     </>
                   )}
                 </>
               )}
             </div>
           }>
      <dl className="s-facts">
        <div><dt>{t("d.state")}</dt><dd><ScanState status={s.status} pct={pct} /></dd></div>
        <div><dt>{t("s.stage")}</dt><dd>{s.stage || "—"}</dd></div>
        <div><dt>{t("d.hosts")}</dt><dd className="mono">{s.hosts_total ? `${n(s.hosts_done || 0)} / ${n(s.hosts_total)}` : "—"}</dd></div>
        <div><dt>{t("s.started")}</dt><dd className="mono">{date(s.created)}</dd></div>
        <div><dt>{t("s.duration")}</dt><dd className="mono">{s.duration_s ? dur(s.duration_s) : running ? dur(Date.now() / 1000 - s.created) : "—"}</dd></div>
        <div><dt>{t("s.opts")}</dt><dd className="mono">{opts.rate_limit || 300} pps{opts.time_window_mins ? ` · ${opts.time_window_mins} min` : ""}{opts.nuclei ? " · nuclei" : ""}{opts.gvm ? " · gvm" : ""}</dd></div>
      </dl>

      <div className="s-band">
        <ol className="steps" aria-label={t("s.steps")}>
          {STEPS.map((k, i) => {
            const st = i < step ? "done" : i === step ? (running ? "active" : "halt") : "todo";
            return (
              <li key={k} className={`step is-${st}`} aria-current={st === "active" ? "step" : undefined}>
                <i aria-hidden="true" />
                <span>{t(`s.step.${k}`)}</span>
              </li>
            );
          })}
        </ol>
        <div className="s-risk">
          <span className="s-risk-num mono">{s.score ?? 0}<small>/100</small></span>
          <span className="s-risk-label">{t("s.score")}</span>
          <ul className="s-sevs" aria-label={t("s.bySev")}>
            {SEVS.slice(0, 4).map((k) => (
              <li key={k}><Sev level={k} compact /><span className="mono">{n(d.counts[k] || 0)}</span><span className="sr-only">{t(`sev.${k}`)}</span></li>
            ))}
          </ul>
        </div>
      </div>

      <div className="tabs" role="tablist" aria-label={t("s.detail")}>
        {tabs.map(([k, label, count]) => (
          <button key={k} type="button" role="tab" id={`tab-${k}`} aria-selected={tab === k} aria-controls={`panel-${k}`}
                  onClick={() => setTab(k)}>
            {label}{count != null && <span className="mono"> {n(count)}</span>}
          </button>
        ))}
      </div>
      <div className="tab-panel" role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
        {tab === "findings" && (
          <FindingsTable findings={d.findings} canEdit={can(user, "read_modify")} onEdit={setEditing} />
        )}
        {tab === "assets" && <Assets assets={d.assets} />}
        {tab === "diff" && <Diff diff={d.diff} running={running} />}
        {tab === "log" && <Log text={s.log} live={running} />}
      </div>

      {editing && <FindingDialog finding={editing} onClose={() => setEditing(null)} onSaved={res.load} onAuthLost={onAuthLost} flash={flash} />}
      {confirmDel && (
        <Confirm title={t("s.deleteTitle", { id: s.id })} body={t("s.deleteBody", { target: s.target })} confirmLabel={t("s.delete")}
                 onClose={() => setConfirmDel(false)}
                 onConfirm={async () => { if (await act(() => api.deleteScan(s.id), t("s.deleted"))) { onChanged(); go("scans"); } }} />
      )}
    </Frame>
  );
}

const KINDS = ["domain", "subdomain", "ip", "port", "web"];

function assetInfo(a, t) {
  const x = a.data || {};
  if (a.kind === "web") return [x.status && `HTTP ${x.status}`, x.title, x.server, (x.tech || []).join(", ")].filter(Boolean).join(" · ");
  if (a.kind === "port") return [x.service, x.version, x.banner && `${t("s.banner")}: ${x.banner}`].filter(Boolean).join(" · ");
  return "";
}

function Assets({ assets }) {
  const { t, n } = useI18n();
  const [kind, setKind] = useState("all");
  const present = KINDS.filter((k) => assets.some((a) => a.kind === k));
  const rows = kind === "all" ? assets : assets.filter((a) => a.kind === kind);
  if (!assets.length) return <p className="q-empty">{t("s.noAssets")}</p>;
  return (
    <div className="ft">
      <div className="toolbar">
        <div className="seg seg-sm" role="group" aria-label={t("s.kind")}>
          <button type="button" aria-pressed={kind === "all"} onClick={() => setKind("all")}>{t("c.all")} <span className="mono">{n(assets.length)}</span></button>
          {present.map((k) => (
            <button key={k} type="button" aria-pressed={kind === k} onClick={() => setKind(k)}>
              {t(`asset.${k}`)} <span className="mono">{n(assets.filter((a) => a.kind === k).length)}</span>
            </button>
          ))}
        </div>
      </div>
      <div className="t-scroll">
        <table className="d-table">
          <thead><tr><th scope="col">{t("s.kind")}</th><th scope="col">{t("s.value")}</th><th scope="col">{t("s.details")}</th></tr></thead>
          <tbody>
            {rows.map((a) => (
              <tr key={a.id}>
                <td className="nowrap">{t(`asset.${a.kind}`)}</td>
                <th scope="row" className="mono f-asset">{a.value}</th>
                <td className="f-fix">{assetInfo(a, t) || <span className="quiet">—</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Diff({ diff, running }) {
  const { t, n } = useI18n();
  if (!diff) return <p className="q-empty">{running ? t("s.diffRunning") : t("s.diffNone")}</p>;
  const groups = [
    ["new", diff.new_assets],
    ["removed", diff.removed_assets],
    ["flapping", diff.flapping_assets || []],
    ["offline", diff.confirmed_offline || []],
  ];
  const fGroups = [
    ["new", t("s.newFindings"), diff.new_findings || []],
    ["removed", t("s.resolvedFindings"), diff.resolved_findings || []],
  ];
  return (
    <div className="diff">
      <p className="quiet diff-against">{t("s.against", { id: diff.against })} <a className="link" href={href("scans", diff.against)}>#{diff.against}</a></p>
      <div className="diff-grid">
        {groups.map(([k, items]) => (
          <section key={k} className="diff-g" aria-labelledby={`dg-${k}`}>
            <h3 id={`dg-${k}`}><KindIcon kind={k} size={14} /> {t(`k.${k}`)} <span className="mono quiet">{n(items.length)}</span></h3>
            {items.length ? (
              <ul className="mono">{items.slice(0, 200).map((x) => <li key={x}>{x}</li>)}</ul>
            ) : <p className="quiet">{t("s.diffEmpty")}</p>}
          </section>
        ))}
      </div>
      <div className="diff-grid diff-grid-f">
        {fGroups.map(([k, label, items]) => (
          <section key={`f-${k}`} className="diff-g" aria-labelledby={`dgf-${k}`}>
            <h3 id={`dgf-${k}`}><KindIcon kind={k === "new" ? "finding" : "removed"} size={14} /> {label} <span className="mono quiet">{n(items.length)}</span></h3>
            {items.length ? (
              <ul>{items.slice(0, 200).map((x) => <li key={x.asset + x.title}><span>{x.title}</span> <code>{x.asset}</code></li>)}</ul>
            ) : <p className="quiet">{t("s.diffEmpty")}</p>}
          </section>
        ))}
      </div>
    </div>
  );
}

function Log({ text, live }) {
  const { t } = useI18n();
  const ref = useRef(null);
  const stick = useRef(true);
  useEffect(() => {
    const el = ref.current;
    if (el && stick.current) el.scrollTop = el.scrollHeight;
  }, [text]);
  return (
    <div className="log-wrap">
      <p className="log-head">
        {live && <span className="d-state st-running"><i aria-hidden="true" />{t("s.live")}</span>}
        <span className="quiet">{t("s.logTail")}</span>
      </p>
      <pre ref={ref} className="log" tabIndex={0}
           onScroll={(e) => { const el = e.currentTarget; stick.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24; }}>
        {text || t("s.logEmpty")}
      </pre>
    </div>
  );
}
