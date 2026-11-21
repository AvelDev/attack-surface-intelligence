import React, { useState } from 'react'
import { I } from './ui.jsx'
import { api, fmtShort, verdict } from './api.js'

const EVERY = { 24: 'codziennie', 168: 'co tydzień', 720: 'co miesiąc' }

/** Alerty: automatyczne ostrzeżenia po pogorszeniu stanu strony. */
export function Alerts({ alerts, onOpen, onRead }) {
  const items = alerts?.items || []
  const unread = items.filter((a) => !a.read)
  if (items.length === 0) return null
  const shown = unread.length ? unread : items.slice(0, 3)
  return (
    <section aria-labelledby="h-alerts">
      <h2 id="h-alerts">Powiadomienia {unread.length > 0 && <span className="chip chip-bad">{unread.length} nowe</span>}</h2>
      <ul className="alerts">
        {shown.map((a) => (
          <li key={a.id} className={`alert ${a.level === 'bad' ? 'alert-bad' : 'alert-warn'}`} role={a.read ? undefined : 'alert'}>
            <I n={a.level === 'bad' ? 'error' : 'warning'} />
            <span>
              <b>{a.target}</b>: {a.message} <span className="muted">({fmtShort(a.created)})</span>{' '}
              <button className="linklike" onClick={() => onOpen(a.scan_id)}>Zobacz wynik</button>
            </span>
          </li>
        ))}
      </ul>
      {unread.length > 0 && <p><button className="btn btn-secondary" onClick={onRead}><I n="check" size={18} />Oznacz jako przeczytane</button></p>}
    </section>
  )
}

/** Strony sprawdzane automatycznie w stałych odstępach. */
export function Monitored({ schedules, onChange, onOpen }) {
  const [ask, setAsk] = useState(null)
  const items = schedules?.items || []
  if (items.length === 0) return null
  const act = async (fn) => { try { await fn() } catch { /* odświeży się przy kolejnym odczycie */ } onChange() }
  return (
    <section aria-labelledby="h-mon">
      <h2 id="h-mon">Strony sprawdzane automatycznie</h2>
      <p className="muted">Program sam powtarza sprawdzenie w wybranych odstępach i wysyła powiadomienie, gdy stan strony się pogorszy.</p>
      <ul className="hist">
        {items.map((h) => {
          const v = h.last_score == null ? null : verdict(h.last_score, {})
          return (
            <li key={h.id} className="hist-row">
              <div className="hist-main">
                {h.last_scan
                  ? <button className="hist-link" onClick={() => onOpen(h.last_scan)}>{h.target}</button>
                  : <span className="hist-link plain">{h.target}</span>}
                <span className="muted">
                  {EVERY[h.interval_hours] || `co ${h.interval_hours} godz.`}
                  {h.enabled ? `, następne sprawdzenie: ${fmtShort(h.next_run)}` : ', wstrzymane'}
                </span>
              </div>
              <div className="hist-state">{v && <span className={`chip chip-${v.tone}`}>{v.title}</span>}</div>
              <div className="hist-act">
                <button className="btn btn-secondary" onClick={() => act(() => api(`/api/schedules/${h.id}`, {
                  method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: !h.enabled }) }))}>
                  {h.enabled ? 'Wstrzymaj' : 'Wznów'}
                </button>
                {ask === h.id ? (
                  <span className="confirm" role="group" aria-label={`Potwierdź zakończenie automatycznego sprawdzania ${h.target}`}>
                    <span>Przestać sprawdzać automatycznie?</span>
                    <button className="btn btn-danger" onClick={() => { setAsk(null); act(() => api(`/api/schedules/${h.id}`, { method: 'DELETE' })) }}>Tak, przestań</button>
                    <button className="btn btn-secondary" onClick={() => setAsk(null)}>Anuluj</button>
                  </span>
                ) : (
                  <button className="btn btn-ghost" onClick={() => setAsk(h.id)} aria-label={`Przestań automatycznie sprawdzać ${h.target}`}><I n="trash" size={18} />Usuń</button>
                )}
              </div>
            </li>
          )
        })}
      </ul>
    </section>
  )
}

/** Ocena ryzyka w czasie: wykres + tekstowy opis (dostępność). */
export function Trend({ trend }) {
  if (!trend || trend.length < 2) return null
  const W = 320, H = 80, P = 8
  const xs = (i) => P + (i * (W - 2 * P)) / (trend.length - 1)
  const ys = (v) => H - P - (v * (H - 2 * P)) / 100
  const pts = trend.map((t, i) => `${xs(i)},${ys(t.score)}`).join(' ')
  const first = trend[0].score, last = trend[trend.length - 1].score
  const word = last < first ? 'poprawiła się' : last > first ? 'pogorszyła się' : 'nie zmieniła'
  return (
    <section aria-labelledby="h-trend">
      <h2 id="h-trend">Ocena ryzyka w czasie</h2>
      <p className="muted">Od {fmtShort(trend[0].created)} ocena {word} (z {first} na {last} na 100, im niżej, tym lepiej).</p>
      <svg className="trend" viewBox={`0 0 ${W} ${H}`} role="img"
        aria-label={`Wykres oceny ryzyka z ostatnich ${trend.length} sprawdzeń: ${trend.map((t) => t.score).join(', ')}`}>
        <line x1={P} x2={W - P} y1={ys(30)} y2={ys(30)} className="trend-grid" />
        <line x1={P} x2={W - P} y1={ys(60)} y2={ys(60)} className="trend-grid" />
        <polyline points={pts} className="trend-line" />
        {trend.map((t, i) => <circle key={t.id} cx={xs(i)} cy={ys(t.score)} r="4" className="trend-dot"><title>{fmtShort(t.created)}: {t.score}/100</title></circle>)}
      </svg>
    </section>
  )
}
