import { Fragment, useMemo, useState } from "react";
import { ChevronRight, Download } from "lucide-react";
import { api } from "../api.js";
import { useI18n } from "../i18n.jsx";
import { Command, LoadState, useResource } from "./ui.jsx";

const PAGE = 100;

/** Czy skan ma co pokazać w zakładce nmap. */
export const hasNmap = (scan, opts) => !!opts.nmap || scan.assets.some((a) => a.kind === "ip" && a.data?.state);

function useHosts(assets) {
  return useMemo(() => {
    const ports = new Map();
    for (const a of assets) {
      if (a.kind !== "port") continue;
      const ip = a.value.slice(0, a.value.lastIndexOf(":"));
      if (!ports.has(ip)) ports.set(ip, []);
      ports.get(ip).push({ ...a.data, id: a.id });
    }
    return assets
      .filter((a) => a.kind === "ip" && (a.data?.state || ports.has(a.value)))
      .map((a) => ({ ip: a.value, ...a.data, ports: (ports.get(a.value) || []).sort((x, y) => x.port - y.port) }))
      .sort((x, y) => x.ip.localeCompare(y.ip, undefined, { numeric: true }));
  }, [assets]);
}

const osName = (h) => (h.os?.[0] ? `${h.os[0].name} (${h.os[0].accuracy}%)` : "");

/** Wyniki nmapa: komendy, hosty z systemem i portami, skrypty NSE, trasa. */
export default function NmapResults({ scanId, assets, running, onAuthLost }) {
  const { t, n } = useI18n();
  const hosts = useHosts(assets);
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(() => new Set(hosts.length === 1 ? [hosts[0].ip] : []));
  const [limit, setLimit] = useState(PAGE);
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return hosts;
    return hosts.filter((h) => JSON.stringify([h.ip, h.hostnames, h.os, h.vendor, h.mac,
      h.ports.map((p) => [p.port, p.service, p.version, p.cpe, (p.scripts || []).map((s) => [s.id, s.output])])]).toLowerCase().includes(needle));
  }, [hosts, q]);
  const toggle = (ip) => setOpen((s) => { const next = new Set(s); if (!next.delete(ip)) next.add(ip); return next; });

  return (
    <div className="ft">
      <Runs scanId={scanId} running={running} tick={hosts.length} onAuthLost={onAuthLost} />
      {!hosts.length ? <p className="q-empty">{t(running ? "nr.wait" : "nr.none")}</p> : (
        <>
          <div className="toolbar">
            <label className="search nr-search">
              <span className="sr-only">{t("nr.search")}</span>
              <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder={t("nr.search")} />
            </label>
            <span className="quiet">{t("nr.count", { n: n(rows.length), p: n(rows.reduce((s, h) => s + h.ports.length, 0)) })}</span>
          </div>
          <div className="t-scroll">
            <table className="d-table nr">
              <thead>
                <tr>
                  <th scope="col">{t("nr.host")}</th><th scope="col">{t("nr.os")}</th><th scope="col">{t("nr.open")}</th>
                  <th scope="col">{t("nr.rest")}</th><th scope="col" className="num">{t("nr.hops")}</th>
                </tr>
              </thead>
              <tbody>
                {rows.slice(0, limit).map((h) => {
                  const on = open.has(h.ip);
                  return (
                    <Fragment key={h.ip}>
                      <tr className={on ? "is-open" : ""}>
                        <th scope="row">
                          <button type="button" className="nr-host" aria-expanded={on} aria-controls={`nr-${h.ip}`} onClick={() => toggle(h.ip)}>
                            <ChevronRight size={13} aria-hidden="true" />
                            <span><code>{h.ip}</code>{h.hostnames?.length > 0 && <small>{h.hostnames[0]}</small>}</span>
                          </button>
                        </th>
                        <td>{osName(h) || <span className="quiet">—</span>}</td>
                        <td className="mono nr-ports">{h.ports.slice(0, 8).map((p) => label(p)).join(" ") || <span className="quiet">—</span>}{h.ports.length > 8 && ` +${h.ports.length - 8}`}</td>
                        <td className="nr-states">{(h.states || []).map((s) => t("nr.state", { n: n(s.count), state: s.state })).join(", ") || <span className="quiet">—</span>}</td>
                        <td className="mono num">{h.distance ?? h.trace?.length ?? "—"}</td>
                      </tr>
                      {on && <tr className="nr-detail" id={`nr-${h.ip}`}><td colSpan={5}><Host h={h} /></td></tr>}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
            {!rows.length && <p className="q-empty nr-none">{t("c.emptyFiltered")}</p>}
            {rows.length > limit && (
              <button type="button" className="btn btn-sm nr-more" onClick={() => setLimit(limit + PAGE)}>{t("nr.more", { n: n(Math.min(PAGE, rows.length - limit)) })}</button>
            )}
          </div>
        </>
      )}
    </div>
  );
}

const label = (p) => (p.proto && p.proto !== "tcp" ? `${p.port}/${p.proto}` : String(p.port));

function Runs({ scanId, running, tick, onAuthLost }) {
  const { t, n, dur } = useI18n();
  const res = useResource(() => api.scanNmap(scanId), onAuthLost, [scanId, running, tick]);
  const [all, setAll] = useState(false);
  if (res.error && !res.data) return <LoadState error={res.error} onRetry={res.load} />;
  const runs = res.data?.runs || [];
  if (!runs.length) return null;
  const shown = all ? runs : runs.slice(0, 2);
  return (
    <section className="nr-runs" aria-label={t("nr.runs")}>
      <ul>
        {shown.map((r) => (
          <li key={r.id}>
            <Command text={r.command} />
            <span className="quiet">
              {t("nr.run", { up: n(r.hosts_up), all: n(r.hosts), d: dur(r.elapsed) })}{!r.complete && ` · ${t("nr.partial")}`}
            </span>
          </li>
        ))}
      </ul>
      <div className="nr-runs-acts">
        {runs.length > 2 && <button type="button" className="link" onClick={() => setAll(!all)}>{all ? t("nr.fewer") : t("nr.allRuns", { n: n(runs.length) })}</button>}
        <a className="btn btn-sm" href={`/api/scans/${scanId}/nmap.xml`}><Download size={13} aria-hidden="true" /> {t("nr.xml")}</a>
      </div>
    </section>
  );
}

function Host({ h }) {
  const { t, n, dur } = useI18n();
  const facts = [
    [t("nr.hostnames"), h.hostnames?.join(", ")],
    ["MAC", h.mac && `${h.mac}${h.vendor ? ` · ${h.vendor}` : ""}`],
    [t("nr.reason"), h.reason],
    [t("nr.uptime"), h.uptime_s && dur(h.uptime_s)],
  ].filter(([, v]) => v);
  return (
    <div className="nr-host-body">
      {facts.length > 0 && <dl className="nr-facts">{facts.map(([k, v]) => <div key={k}><dt>{k}</dt><dd className="mono">{v}</dd></div>)}</dl>}
      {h.timed_out && <p className="nm-note">{t("nr.timedOut")}</p>}
      {h.ports.length > 0 && (
        <table className="d-table nr-ptable">
          <thead><tr><th scope="col">{t("nr.port")}</th><th scope="col">{t("nr.service")}</th><th scope="col">{t("nr.version")}</th><th scope="col">{t("nr.reason")}</th></tr></thead>
          <tbody>
            {h.ports.map((p) => (
              <Fragment key={p.id}>
                <tr>
                  <th scope="row" className="mono nowrap">{p.port}<span className="quiet">/{p.proto || "tcp"}</span></th>
                  <td className="nowrap">{p.service || <span className="quiet">—</span>}{p.service && p.probed === false && <span className="quiet" title={t("nr.guess")}> ?</span>}</td>
                  <td>
                    {[p.version, p.info && `(${p.info})`].filter(Boolean).join(" ") || <span className="quiet">—</span>}
                    {(p.cpe || []).map((c) => <code key={c} className="nr-cpe">{c}</code>)}
                  </td>
                  <td className="quiet nowrap">{p.reason || "—"}</td>
                </tr>
                {p.scripts?.length > 0 && <tr className="nr-scripts"><td colSpan={4}><Scripts items={p.scripts} /></td></tr>}
              </Fragment>
            ))}
          </tbody>
        </table>
      )}
      <div className="nr-cols">
        {h.states?.length > 0 && (
          <section>
            <h4>{t("nr.otherStates")}</h4>
            <ul className="nr-list">
              {h.states.map((s) => (
                <li key={s.proto + s.state}>
                  <span className="mono">{n(s.count)}</span> {s.proto} {s.state} {s.reason && <span className="quiet">({s.reason})</span>}
                  {s.ports.length > 0 && <code className="nr-wrap">{s.ports.join(", ")}</code>}
                </li>
              ))}
            </ul>
          </section>
        )}
        {h.os?.length > 0 && (
          <section>
            <h4>{t("nr.os")}</h4>
            <ul className="nr-list">
              {h.os.map((o) => <li key={o.name}><span className="mono">{o.accuracy}%</span> {o.name} {o.type && <span className="quiet">({o.type})</span>}</li>)}
            </ul>
          </section>
        )}
        {h.trace?.length > 0 && (
          <section>
            <h4>{t("nr.trace")}</h4>
            <ol className="nr-list nr-trace">
              {h.trace.map((x) => (
                <li key={x.ttl}><span className="mono">{x.ttl}</span> <code>{x.ip}</code> {x.host && <span>{x.host}</span>} {x.rtt != null && <span className="quiet mono">{x.rtt} ms</span>}</li>
              ))}
            </ol>
          </section>
        )}
      </div>
      {h.scripts?.length > 0 && <section><h4>{t("nr.hostScripts")}</h4><Scripts items={h.scripts} /></section>}
    </div>
  );
}

function Scripts({ items }) {
  return (
    <dl className="nr-nse">
      {items.map((s, i) => (
        <div key={s.id + i}>
          <dt><a className="link mono" href={`https://nmap.org/nsedoc/scripts/${s.id}.html`} target="_blank" rel="noopener noreferrer">{s.id}</a></dt>
          <dd><pre tabIndex={s.output.length > 600 ? 0 : undefined}>{s.output || "—"}</pre></dd>
        </div>
      ))}
    </dl>
  );
}
