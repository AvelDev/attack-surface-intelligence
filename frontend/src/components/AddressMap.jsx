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
                <GraphView blocks={m.blocks} filter={filter} onFilter={onFilter} />
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
  // Mniej płytek niż mieści się w jednym rzędzie (typowo pojedynczy /24) - wyśrodkuj ten
  // rząd, zamiast zostawiać go przyklejonego do lewej krawędzi ogromnego, pustego panelu.
  // Przy pełnej siatce (więcej rzędów) offsetX=0 - zwykłe wyrównanie do lewej, jak dotąd.
  const usedCols = Math.min(cols, blocks.length);
  const offsetX = blocks.length <= cols ? Math.max(0, (width - (usedCols * TILE + (usedCols - 1) * GAP_X)) / 2) : 0;
  const pos = (i) => ({ x: offsetX + (i % cols) * (TILE + GAP_X), y: Math.floor(i / cols) * (LABEL_H + TILE + GAP_Y) + LABEL_H });

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
      {width > 0 &&
        blocks.map((b, i) => {
          const { x, y } = pos(i);
          return b.hosts.map((h) => {
            const active = filter?.type === "host" && filter.value === h.ip;
            const label = t("b.hostLabel", { ip: h.ip, services: h.services, changes: h.changes })
              + (h.state ? ` · ${t(`k.${h.state}`)}` : "");
            return (
              <button
                key={h.ip}
                type="button"
                className={`host-dot${active ? " is-active" : ""}`}
                style={{ left: x + (h.octet % 16) * PITCH, top: y + Math.floor(h.octet / 16) * PITCH }}
                title={label}
                aria-pressed={active}
                aria-label={label}
                onClick={() => onFilter(active ? null : { type: "host", value: h.ip, label: h.ip })}
              />
            );
          });
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

/* ---------- mała skala (≤16 hostów, np. lab): graf powiązań host <-> port, węzły do
   przeciągania - fizyka (odpychanie + sprężyny wzdłuż krawędzi) liczona w rAF i wpisywana
   bezpośrednio w atrybuty SVG przez refy, żeby nie przerysowywać Reacta 60 razy/s. ---------- */

const GRAPH_H = 420;
const HOST_R = 10, PORT_R = 6.5;
const DRAG_CLICK_PX = 5; // poniżej tego ruchu puszczenie liczy się jako klik, nie przeciągnięcie

function buildGraph(hosts) {
  const nodes = [];
  const links = [];
  const cx = 0, cy = 0;
  hosts.forEach((h, hi) => {
    const a = (hi / Math.max(1, hosts.length)) * Math.PI * 2;
    const hr = 60 + 40 * Math.min(3, Math.floor(hosts.length / 6));
    const hx = cx + Math.cos(a) * hr, hy = cy + Math.sin(a) * hr;
    nodes.push({ id: `h:${h.ip}`, kind: "host", host: h, x: hx, y: hy, vx: 0, vy: 0 });
    (h.ports || []).forEach((p, pi) => {
      const pcount = (h.ports || []).length;
      const pa = a + ((pi - (pcount - 1) / 2) / Math.max(1, pcount)) * 1.4;
      const pr = hr + 46;
      nodes.push({
        id: `p:${h.ip}:${p.port}`, kind: "port", host: h, port: p,
        x: cx + Math.cos(pa) * pr, y: cy + Math.sin(pa) * pr, vx: 0, vy: 0,
      });
      links.push({ a: `h:${h.ip}`, b: `p:${h.ip}:${p.port}` });
    });
  });
  return { nodes, links };
}

function GraphView({ blocks, filter, onFilter }) {
  const { t } = useI18n();
  const hosts = useMemo(() => blocks.flatMap((b) => b.hosts), [blocks]);
  const wrap = useRef(null);
  const svgRef = useRef(null);
  const [width, setWidth] = useState(0);
  const nodeRefs = useRef(new Map());
  const linkRefs = useRef(new Map());

  const sig = useMemo(() => hosts.map((h) => h.ip + ":" + (h.ports || []).map((p) => p.port).join(",")).join("|"), [hosts]);
  const graph = useMemo(() => buildGraph(hosts), [sig]); // eslint-disable-line react-hooks/exhaustive-deps

  useLayoutEffect(() => {
    const el = wrap.current;
    const ro = new ResizeObserver(([e]) => setWidth(Math.floor(e.contentRect.width)));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    if (!width) return;
    const { nodes, links } = graph;
    const byId = new Map(nodes.map((n) => [n.id, n]));
    const cx = width / 2, cy = GRAPH_H / 2;
    // Przesunięcie startowe tylko RAZ dla danego obiektu grafu (nie przy każdym przebiegu
    // efektu) - inaczej zmiana szerokości okna (sama w sobie nie buduje nowego grafu, bo
    // zależność efektu to [graph, width, themeTick]) dokładałaby cx/cy po raz kolejny i węzły
    // uciekałyby w nieskończoność przy każdym resize.
    if (!graph._centered) {
      nodes.forEach((n) => { n.x += cx; n.y += cy; });
      graph._centered = true;
    }
    let raf = 0;
    let dragging = null; // { node, pointerId, moved }

    const tick = () => {
      // odpychanie (O(n²), bezpieczne przy skali tego widoku - ≤16 hostów + ich porty)
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i], b = nodes[j];
          let dx = a.x - b.x, dy = a.y - b.y;
          let d2 = dx * dx + dy * dy || 0.01;
          if (d2 > 220 * 220) continue;
          const d = Math.sqrt(d2);
          const f = 900 / d2;
          dx /= d; dy /= d;
          if (a !== dragging?.node) { a.vx += dx * f; a.vy += dy * f; }
          if (b !== dragging?.node) { b.vx -= dx * f; b.vy -= dy * f; }
        }
      }
      // sprężyny wzdłuż krawędzi host<->port
      links.forEach((l) => {
        const a = byId.get(l.a), b = byId.get(l.b);
        if (!a || !b) return;
        const dx = b.x - a.x, dy = b.y - a.y;
        const d = Math.sqrt(dx * dx + dy * dy) || 0.01;
        const rest = 70, k = 0.02;
        const f = (d - rest) * k;
        const ux = dx / d, uy = dy / d;
        if (a !== dragging?.node) { a.vx += ux * f; a.vy += uy * f; }
        if (b !== dragging?.node) { b.vx -= ux * f; b.vy -= uy * f; }
      });
      // delikatne dociąganie do środka, żeby graf nie odpłynął poza widok
      nodes.forEach((n) => {
        if (n === dragging?.node) return;
        n.vx += (cx - n.x) * 0.0015;
        n.vy += (cy - n.y) * 0.0015;
        n.vx *= 0.82; n.vy *= 0.82;
        n.x += n.vx; n.y += n.vy;
      });
      nodes.forEach((n) => {
        const el = nodeRefs.current.get(n.id);
        if (el) el.setAttribute("transform", `translate(${n.x},${n.y})`);
      });
      links.forEach((l) => {
        const a = byId.get(l.a), b = byId.get(l.b);
        const el = linkRefs.current.get(l.a + "|" + l.b);
        if (el && a && b) { el.setAttribute("x1", a.x); el.setAttribute("y1", a.y); el.setAttribute("x2", b.x); el.setAttribute("y2", b.y); }
      });
      raf = requestAnimationFrame(tick);
    };

    if (reduced()) {
      nodes.forEach((n) => { const el = nodeRefs.current.get(n.id); if (el) el.setAttribute("transform", `translate(${n.x},${n.y})`); });
      links.forEach((l) => {
        const a = byId.get(l.a), b = byId.get(l.b);
        const el = linkRefs.current.get(l.a + "|" + l.b);
        if (el && a && b) { el.setAttribute("x1", a.x); el.setAttribute("y1", a.y); el.setAttribute("x2", b.x); el.setAttribute("y2", b.y); }
      });
    } else {
      raf = requestAnimationFrame(tick);
    }

    const toSvgPoint = (e) => {
      const pt = svgRef.current.createSVGPoint();
      pt.x = e.clientX; pt.y = e.clientY;
      const m = svgRef.current.getScreenCTM().inverse();
      const p = pt.matrixTransform(m);
      return { x: p.x, y: p.y };
    };
    const onMove = (e) => {
      if (!dragging || dragging.pointerId !== e.pointerId) return;
      const p = toSvgPoint(e);
      dragging.node.x = p.x; dragging.node.y = p.y;
      dragging.node.vx = 0; dragging.node.vy = 0;
      if (Math.hypot(p.x - dragging.start.x, p.y - dragging.start.y) > DRAG_CLICK_PX) dragging.moved = true;
      const el = nodeRefs.current.get(dragging.node.id);
      if (el) el.setAttribute("transform", `translate(${p.x},${p.y})`);
    };
    const onUp = (e) => {
      if (!dragging || dragging.pointerId !== e.pointerId) return;
      const wasClick = !dragging.moved;
      const n = dragging.node;
      dragging = null;
      if (wasClick) n.onActivate?.();
    };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
    svgRef.current._startDrag = (node, e) => {
      dragging = { node, pointerId: e.pointerId, start: toSvgPoint(e), moved: false };
    };

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
    };
  }, [graph, width]);

  const activate = (id, fn) => {
    const n = graph.nodes.find((x) => x.id === id);
    if (n) n.onActivate = fn;
  };

  return (
    <div className="graph-wrap" ref={wrap}>
      <svg ref={svgRef} className="graph-svg" width={width || 1} height={GRAPH_H} role="group" aria-label={t("b.graphLabel")}>
        <g>
          {graph.links.map((l) => (
            <line key={l.a + "|" + l.b} ref={(el) => { const k = l.a + "|" + l.b; if (el) linkRefs.current.set(k, el); else linkRefs.current.delete(k); }} className="graph-link" />
          ))}
        </g>
        <g>
          {graph.nodes.map((n) => {
            if (n.kind === "host") {
              const h = n.host;
              const hostActive = filter?.type === "host" && filter.value === h.ip;
              activate(n.id, () => onFilter(hostActive ? null : { type: "host", value: h.ip, label: h.ip }));
              const label = t("b.hostLabel", { ip: h.ip, services: h.services, changes: h.changes });
              return (
                <g
                  key={n.id}
                  ref={(el) => { if (el) nodeRefs.current.set(n.id, el); else nodeRefs.current.delete(n.id); }}
                  className={`graph-node graph-host st-${h.state || (h.alive ? "live" : "gone")}${hostActive ? " is-active" : ""}`}
                  tabIndex={0} role="button" aria-pressed={hostActive} aria-label={label}
                  onPointerDown={(e) => { e.currentTarget.setPointerCapture(e.pointerId); svgRef.current._startDrag(n, e); }}
                  onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); n.onActivate(); } }}
                >
                  <circle r={HOST_R} />
                  <text className="graph-label mono" y={-HOST_R - 6}>{h.ip}</text>
                </g>
              );
            }
            const p = n.port, h = n.host;
            const crit = p.severity === "critical";
            const st = p.state || (p.alive ? "live" : "gone");
            const active = filter?.type === "asset" && filter.value === p.asset;
            activate(n.id, () => onFilter(active ? null : { type: "asset", value: p.asset, port: `${h.ip}:${p.port}`, label: `${h.ip}:${p.port}` }));
            const label = t("b.portLabel", { port: p.port, label: p.label }) + (p.state ? ` · ${t(`k.${p.state}`)}` : "");
            return (
              <g
                key={n.id}
                ref={(el) => { if (el) nodeRefs.current.set(n.id, el); else nodeRefs.current.delete(n.id); }}
                className={`graph-node graph-port st-${st}${crit ? " is-crit" : ""}${active ? " is-active" : ""}`}
                tabIndex={0} role="button" aria-pressed={active} aria-label={label}
                onPointerDown={(e) => { e.currentTarget.setPointerCapture(e.pointerId); svgRef.current._startDrag(n, e); }}
                onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); n.onActivate(); } }}
              >
                <title>{`${p.port} · ${p.label}`}</title>
                <circle r={PORT_R} />
                <text className="graph-label mono" y={PORT_R + 12}>{shortLabel(p.label) || p.port}</text>
              </g>
            );
          })}
        </g>
      </svg>
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
