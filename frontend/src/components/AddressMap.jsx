import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { useI18n } from "../i18n.jsx";
import Frame from "./Frame.jsx";

const PITCH = 5;          // odstęp kropek w płytce /24 (16 × 16 adresów)
const TILE = 16 * PITCH;  // 80px
const GAP_X = 18;
const LABEL_H = 22;       // miejsce na etykietę prefiksu i iglice nad płytką
const GAP_Y = 14;

const reduced = () => window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

function useThemeTick() {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const mo = new MutationObserver(() => setTick((v) => v + 1));
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    return () => mo.disconnect();
  }, []);
  return tick;
}

function palette() {
  const cs = getComputedStyle(document.documentElement);
  const g = (n) => cs.getPropertyValue(n).trim();
  return { dot: g("--dot"), live: g("--dot-live"), change: g("--change"), crit: g("--crit"), ink3: g("--ink-3") };
}

export default function AddressMap({ data, focused, scan, onScan, filter, onFilter, historyAll, onAdd }) {
  const { t, n } = useI18n();
  const ranges = useMemo(() => {
    const byId = Object.fromEntries(data.ranges.map((r) => [r.id, r]));
    return [...data.map.ranges]
      .filter((m) => m.host_count > 0 || m.domains.length)
      .map((m) => ({ ...m, meta: byId[m.range] }))
      .sort((a, b) => changesOf(b.meta) - changesOf(a.meta));
  }, [data]);
  // przy wielu zakresach te bez zmian zwijają się do jednej linii: pole zostaje dla tego, co się ruszyło
  const quiet = ranges.length > 1 ? ranges.filter((m) => !changesOf(m.meta)) : [];
  const loud = ranges.filter((m) => !quiet.includes(m));

  const hosts = data.ranges.reduce((s, r) => s + r.hosts_alive, 0);
  const services = data.ranges.reduce((s, r) => s + r.services, 0);

  return (
    <Frame tag="B" id="mod-b" className="mod-b" title={t("b.title")} meta={t("b.sub", { hosts: n(hosts), services: n(services) })}>
      {ranges.length === 0 ? (
        <EmptyField onAdd={onAdd} />
      ) : (
        <div className="b-scroll" tabIndex={-1}>
          {loud.map((m) => (
            <section key={m.range} className="b-range" aria-label={m.name}>
              <header className="b-range-head">
                <span className="b-range-name mono">{m.name}</span>
                <span className="b-range-meta">
                  {n(m.meta.hosts_alive)} · {changesOf(m.meta) ? <b className="change-ink">{n(changesOf(m.meta))} {t("d.changes").toLowerCase()}</b> : "0"}
                </span>
              </header>
              {isDetail(m) ? (
                <PortBands blocks={m.blocks} filter={filter} onFilter={onFilter} />
              ) : (
                <Tiles blocks={m.blocks} filter={filter} onFilter={onFilter} />
              )}
              {m.domains.length > 0 && (
                <p className="b-domains">
                  <span>{t("b.domains")}:</span>{" "}
                  {m.domains.slice(0, 8).map((d) => <code key={d}>{d}</code>)}
                  {m.domains.length > 8 && <span> +{m.domains.length - 8}</span>}
                </p>
              )}
            </section>
          ))}
          {quiet.length > 0 && (
            <section className="b-range b-quiet" aria-label={t("b.quiet")}>
              <header className="b-range-head"><span className="b-range-name">{t("b.quiet")}</span></header>
              <ul>
                {quiet.map((m) => (
                  <li key={m.range}>
                    <span className="mono">{m.name}</span>
                    <span className="b-range-meta">{t("b.quietLine", { hosts: n(m.meta.hosts_alive), services: n(m.meta.services) })}</span>
                  </li>
                ))}
              </ul>
            </section>
          )}
        </div>
      )}
      <Legend />
      {focused ? <Scrubber focused={focused} scan={scan} onScan={onScan} /> : <DayScrubber history={historyAll?.length ? historyAll : data.history} scan={scan} onScan={onScan} />}
    </Frame>
  );
}

const isDetail = (m) => m.blocks.some((b) => b.hosts.some((h) => h.ports));

function changesOf(r) {
  if (!r) return 0;
  const c = r.counts;
  return (c.new || 0) + (c.removed || 0) + (c.changed || 0) + (c.flapping || 0) + (c.offline || 0);
}

/* ---------- duża skala: płytki /24, każda kropka to jeden adres ---------- */

function Tiles({ blocks, filter, onFilter }) {
  const { t } = useI18n();
  const wrap = useRef(null);
  const canvas = useRef(null);
  const [width, setWidth] = useState(0);
  const themeTick = useThemeTick();
  const grow = useRef({ from: 0, start: 0 });

  useLayoutEffect(() => {
    const el = wrap.current;
    const ro = new ResizeObserver(([e]) => setWidth(Math.floor(e.contentRect.width)));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const cols = Math.max(1, Math.floor((width + GAP_X) / (TILE + GAP_X)));
  const rows = Math.ceil(blocks.length / cols);
  const height = rows * (LABEL_H + TILE + GAP_Y);
  const pos = (i) => ({ x: (i % cols) * (TILE + GAP_X), y: Math.floor(i / cols) * (LABEL_H + TILE + GAP_Y) + LABEL_H });

  // iglice rosną przy każdej nowej porcji danych (jedyny autorski ruch na ekranie)
  const sig = useMemo(() => blocks.map((b) => b.prefix + b.hosts.reduce((s, h) => s + h.changes, 0)).join("|"), [blocks]);
  useEffect(() => { grow.current = { start: performance.now() }; }, [sig]);

  useEffect(() => {
    const cv = canvas.current;
    if (!cv || !width) return;
    const dpr = window.devicePixelRatio || 1;
    cv.width = width * dpr;
    cv.height = height * dpr;
    cv.style.width = `${width}px`;
    cv.style.height = `${height}px`;
    const ctx = cv.getContext("2d");
    const pal = palette();
    let raf = 0;
    const draw = (now) => {
      const k = reduced() ? 1 : Math.min(1, (now - grow.current.start) / 650);
      const e = 1 - Math.pow(1 - k, 4);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, width, height);
      blocks.forEach((b, i) => {
        const { x, y } = pos(i);
        const byOctet = new Map(b.hosts.map((h) => [h.octet, h]));
        for (let o = 0; o < 256; o++) {
          const cx = x + (o % 16) * PITCH + PITCH / 2;
          const cy = y + Math.floor(o / 16) * PITCH + PITCH / 2;
          const h = byOctet.get(o);
          if (!h) {
            ctx.fillStyle = pal.dot;
            ctx.fillRect(cx - 0.6, cy - 0.6, 1.2, 1.2);
            continue;
          }
          drawHost(ctx, pal, h, cx, cy);
        }
        // iglice nad hostami ze zmianami
        b.hosts.forEach((h) => {
          if (!h.changes && h.severity !== "critical") return;
          if (!h.state && h.severity !== "critical") return;
          const cx = x + (h.octet % 16) * PITCH + PITCH / 2;
          const cy = y + Math.floor(h.octet / 16) * PITCH + PITCH / 2;
          const crit = h.severity === "critical";
          const len = (crit ? 46 : 16 + Math.min(4, h.changes) * 6) * e;
          const col = crit ? pal.crit : pal.change;
          const grad = ctx.createLinearGradient(0, cy, 0, cy - len);
          grad.addColorStop(0, col);
          grad.addColorStop(1, "transparent");
          ctx.strokeStyle = grad;
          ctx.lineWidth = crit ? 1.6 : 1.2;
          ctx.beginPath();
          ctx.moveTo(cx, cy - 2);
          ctx.lineTo(cx, cy - 2 - len);
          ctx.stroke();
        });
      });
      if (k < 1) raf = requestAnimationFrame(draw);
    };
    raf = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(raf);
  }, [blocks, width, height, cols, themeTick, sig]);

  return (
    <div className="tiles" ref={wrap} style={{ height }}>
      <canvas ref={canvas} aria-hidden="true" />
      {width > 0 &&
        blocks.map((b, i) => {
          const { x, y } = pos(i);
          const alive = b.hosts.filter((h) => h.alive).length;
          const changes = b.hosts.reduce((s, h) => s + (h.state ? 1 : 0), 0);
          const crit = b.hosts.some((h) => h.severity === "critical");
          const active = filter?.type === "block" && filter.value === b.prefix;
          return (
            <button
              key={b.prefix}
              type="button"
              className={`tile${active ? " is-active" : ""}${changes ? " has-change" : ""}${crit ? " has-crit" : ""}`}
              style={{ left: x - 3, top: y - LABEL_H, width: TILE + 6, height: TILE + LABEL_H + 3 }}
              aria-pressed={active}
              aria-label={t("b.tileLabel", { prefix: b.prefix, alive, changes })}
              onClick={() => onFilter(active ? null : { type: "block", value: b.prefix, label: b.prefix })}
            >
              <span className="tile-label mono">{b.prefix.replace(/\.0\/24$/, "")}</span>
            </button>
          );
        })}
    </div>
  );
}

function drawHost(ctx, pal, h, cx, cy) {
  const crit = h.severity === "critical";
  const col = crit ? pal.crit : h.state ? pal.change : pal.live;
  ctx.fillStyle = col;
  ctx.strokeStyle = col;
  ctx.lineWidth = 1;
  if (h.state === "removed" || h.state === "offline" || !h.alive) {
    ctx.beginPath();
    ctx.arc(cx, cy, 1.7, 0, Math.PI * 2);
    ctx.stroke();
  } else if (h.state === "flapping") {
    ctx.beginPath();
    ctx.arc(cx, cy, 1.8, 0, Math.PI * 2);
    ctx.stroke();
    ctx.beginPath();
    ctx.arc(cx, cy, 1.8, Math.PI / 2, (Math.PI * 3) / 2);
    ctx.fill();
  } else if (h.state === "changed") {
    ctx.fillRect(cx - 1.8, cy - 1.8, 3.6, 3.6);
  } else {
    ctx.beginPath();
    ctx.arc(cx, cy, h.state ? 2 : 1.5, 0, Math.PI * 2);
    ctx.fill();
  }
}

/* ---------- mała skala (≤16 hostów, np. lab): każdy host to pasmo portów ---------- */

function PortBands({ blocks, filter, onFilter }) {
  const { t } = useI18n();
  const hosts = blocks.flatMap((b) => b.hosts);
  return (
    <div className="bands">
      {hosts.map((h) => {
        const hostActive = filter?.type === "host" && filter.value === h.ip;
        return (
          <div className="band" key={h.ip}>
            <button
              type="button"
              className={`band-host${hostActive ? " is-active" : ""}`}
              aria-pressed={hostActive}
              aria-label={t("b.hostLabel", { ip: h.ip, services: h.services, changes: h.changes })}
              onClick={() => onFilter(hostActive ? null : { type: "host", value: h.ip, label: h.ip })}
            >
              <span className={`band-dot st-${h.state || (h.alive ? "live" : "gone")}`} aria-hidden="true" />
              <span className="mono">{h.ip}</span>
              <small>{h.services} · {h.changes}</small>
            </button>
            <ol className="band-ports">
              {(h.ports || []).map((p) => {
                const crit = p.severity === "critical";
                const st = p.state || (p.alive ? "live" : "gone");
                const active = filter?.type === "asset" && filter.value === p.asset;
                return (
                  <li key={p.port}>
                    <button
                      type="button"
                      className={`port st-${st}${crit ? " is-crit" : ""}${active ? " is-active" : ""}`}
                      aria-pressed={active}
                      aria-label={t("b.portLabel", { port: p.port, label: p.label }) + (p.state ? ` · ${t(`k.${p.state}`)}` : "")}
                      title={`${p.port} · ${p.label}`}
                      onClick={() => onFilter(active ? null : { type: "asset", value: p.asset, port: `${h.ip}:${p.port}`, label: `${h.ip}:${p.port}` })}
                    >
                      <span className="port-spike" aria-hidden="true" />
                      <span className="port-dot" aria-hidden="true" />
                      <span className="port-num mono">{p.port}</span>
                      <span className="port-svc">{shortLabel(p.label)}</span>
                    </button>
                  </li>
                );
              })}
            </ol>
          </div>
        );
      })}
    </div>
  );
}

function shortLabel(label) {
  const s = (label || "").split(" · ").filter((x) => !/^\d{3}$/.test(x))[0] || label || "";
  return s.length > 18 ? s.slice(0, 17) + "…" : s;
}

function Legend() {
  const { t } = useI18n();
  const items = [
    ["live", "b.legend.live"], ["empty", "b.legend.empty"], ["new", "b.legend.change"],
    ["removed", "b.legend.removed"], ["flapping", "b.legend.flap"], ["crit", "b.legend.crit"],
  ];
  return (
    <ul className="legend" aria-label="Legenda">
      {items.map(([k, key]) => (
        <li key={k}><span className={`lg lg-${k}`} aria-hidden="true" />{t(key)}</li>
      ))}
    </ul>
  );
}

/** Widok wszystkich zakresów: suwak dni; wybrany dzień przemapowuje całe pole na ostatnie przebiegi sprzed jego końca. */
function DayScrubber({ history, scan, onScan }) {
  const passes = (history || []).map((p) => ({ id: `at:${Math.round(p.t + 43199)}`, t: p.t }));
  return <Scrubber focused={{ passes }} scan={scan} onScan={onScan} isDay />;
}

function Scrubber({ focused, scan, onScan, isDay = false }) {
  const { t, day, date } = useI18n();
  const passes = focused.passes || [];
  if (passes.length < 2) return null;
  const latest = passes[passes.length - 1].id;
  const current = scan || focused.base_scan || latest;
  const viewing = scan && scan !== latest ? passes.find((p) => p.id === scan) : null;
  const onKey = (e) => {
    const i = passes.findIndex((p) => p.id === current);
    if (e.key === "ArrowLeft" && i > 0) { e.preventDefault(); onScan(passes[i - 1].id === latest ? null : passes[i - 1].id); }
    if (e.key === "ArrowRight" && i < passes.length - 1) { e.preventDefault(); onScan(passes[i + 1].id === latest ? null : passes[i + 1].id); }
  };
  return (
    <div className="scrub">
      <div className="scrub-track" role="radiogroup" aria-label={t("b.scrub")} onKeyDown={onKey}>
        {passes.map((p, i) => {
          const on = p.id === current;
          return (
            <button
              key={p.id}
              type="button"
              role="radio"
              aria-checked={on}
              tabIndex={on ? 0 : -1}
              className={`scrub-pass${on ? " is-on" : ""}`}
              style={{ left: `${passes.length === 1 ? 0 : (i / (passes.length - 1)) * 100}%` }}
              onClick={() => onScan(p.id === latest ? null : p.id)}
              aria-label={isDay ? day(p.t) : `#${p.id} · ${date(p.t)}`}
            >
              <span className="scrub-tick" aria-hidden="true" />
              <span className="scrub-date">{p.id === latest ? t("b.scrubLatest") : day(p.t)}</span>
            </button>
          );
        })}
      </div>
      {viewing && (
        <p className="scrub-note">
          {isDay ? t("b.scrubViewingDay", { when: day(viewing.t) }) : t("b.scrubViewing", { id: viewing.id, when: date(viewing.t) })}{" "}
          <button type="button" className="link" onClick={() => onScan(null)}>{t("b.backToLatest")}</button>
        </p>
      )}
    </div>
  );
}

function EmptyField({ onAdd }) {
  const { t } = useI18n();
  return (
    <div className="b-empty">
      <div className="b-empty-field" aria-hidden="true" />
      <p className="b-empty-title">{t("b.empty")}</p>
      <p className="quiet">{t("b.emptyHint")}</p>
      {onAdd ? <button type="button" className="btn btn-primary" onClick={onAdd}>{t("b.emptyCta")}</button>
        : <a className="btn" href="#/scans">{t("nav.ranges")}</a>}
    </div>
  );
}
