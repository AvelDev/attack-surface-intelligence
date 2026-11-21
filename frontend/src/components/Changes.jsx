import { useI18n } from "../i18n.jsx";
import Frame from "./Frame.jsx";
import KindIcon from "./KindIcon.jsx";

const ROWS = ["new", "removed", "changed", "flapping", "offline", "critical"];

export default function Changes({ data, focused, filter, onFilter }) {
  const { t, n } = useI18n();
  const c = focused ? focused.counts : data.totals;
  const total = (c.new || 0) + (c.removed || 0) + (c.changed || 0) + (c.flapping || 0) + (c.offline || 0);
  const firstPass = focused ? focused.first_pass : data.ranges.length > 0 && data.ranges.every((r) => r.first_pass);
  const history = focused ? focused.history : data.history;
  const meta = focused
    ? focused.prev_scan ? t("a.vs", { base: focused.base_scan, prev: focused.prev_scan }) : null
    : t("a.multi", { n: data.ranges.length });

  return (
    <Frame tag="A" id="mod-a" className="mod-a" title={t("a.title")} meta={meta}>
      {data.ranges.length === 0 ? (
        <p className="quiet">—</p>
      ) : firstPass ? (
        <p className="quiet">{t("a.firstPass")}</p>
      ) : (
        <>
          <div className="a-total">
            <span className="a-num mono">{n(total)}</span>
            <span className="a-label">{t("a.total")}</span>
          </div>
          <History points={history} label={focused ? t("a.history") : t("a.historyDays")} />
        </>
      )}
      <ul className="a-rows">
        {ROWS.map((k) => {
          const v = c[k] || 0;
          if (k === "offline" && !v) return null;
          const active = filter?.type === "kind" && filter.value === k;
          return (
            <li key={k}>
              <button
                type="button"
                className={`a-row${active ? " is-active" : ""}${v ? "" : " is-zero"}`}
                aria-pressed={active}
                title={t("a.filterHint")}
                onClick={() => onFilter(active ? null : { type: "kind", value: k, label: t(`k.${k}`) })}
              >
                <KindIcon kind={k} />
                <span className="a-row-label">{t(`k.${k}`)}</span>
                {k === "critical" && c.high ? <span className="a-row-sub">{t("a.critHigh", { n: n(c.high) })}</span> : null}
                <span className={`a-row-val mono${k === "critical" && v ? " crit" : ""}`}>{n(v)}</span>
              </button>
            </li>
          );
        })}
      </ul>
    </Frame>
  );
}

/** Historia liczby zmian z zaznaczonym momentem skoku (onset). */
function History({ points, label }) {
  const { t, day } = useI18n();
  if (!points || points.length < 2) return null;
  const W = 280, H = 56, P = 3;
  const max = Math.max(1, ...points.map((p) => p.changes));
  const x = (i) => P + (i * (W - 2 * P)) / (points.length - 1);
  const y = (v) => H - P - (v / max) * (H - 2 * P - 8);
  const line = points.map((p, i) => `${x(i).toFixed(1)},${y(p.changes).toFixed(1)}`).join(" ");
  // onset: ostatni punkt, w którym liczba zmian wyraźnie skoczyła względem mediany poprzednich
  let onset = -1;
  for (let i = points.length - 1; i > 0; i--) {
    const before = points.slice(0, i).map((p) => p.changes).sort((a, b) => a - b);
    const med = before[Math.floor(before.length / 2)];
    if (points[i].changes > Math.max(2, med * 1.8)) { onset = i; break; }
  }
  const desc = points.map((p) => `${day(p.t)}: ${p.changes}`).join(", ");
  return (
    <figure className="a-hist">
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" role="img" aria-label={`${label}. ${desc}`}>
        {points.map((_, i) => (
          <line key={i} x1={x(i)} x2={x(i)} y1={P} y2={H - P} className="a-hist-grid" />
        ))}
        {onset > 0 && <line x1={x(onset)} x2={x(onset)} y1={0} y2={H} className="a-hist-onset" />}
        <polyline points={line} className="a-hist-line" fill="none" />
        {points.map((p, i) => (
          // zero-długości linia z okrągłym końcem: kropka nie rozciąga się razem z wykresem
          <line key={i} x1={x(i)} x2={x(i)} y1={y(p.changes)} y2={y(p.changes)} className={i === onset ? "a-hist-dot is-onset" : "a-hist-dot"} />
        ))}
      </svg>
      <figcaption>
        <span>{label}</span>
        {onset > 0 && <span className="a-hist-onset-label mono">{t("a.onset")} {day(points[onset].t)}</span>}
      </figcaption>
    </figure>
  );
}
