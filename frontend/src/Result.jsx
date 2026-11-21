import React, { useEffect, useRef, useState } from 'react'
import { I, SevBadge } from './ui.jsx'
import { Graph } from './Graph.jsx'
import { Trend } from './Monitor.jsx'
import {
  PL, WHEN, KIND_PL, STEPS, isRunning, verdict, plural, fmtTime, assetLabel, assetInfo, explain, niceTitle, stepIndex,
} from './api.js'

export function Result({ detail, error, onBack, onRescan }) {
  if (error && !detail) {
    return (
      <div className="stack-lg">
        <BackLink onBack={onBack} />
        <div className="alert alert-bad" role="alert"><I n="error" /><span>{error}</span></div>
      </div>
    )
  }
  if (!detail) return <div className="stack-lg"><BackLink onBack={onBack} /><p className="muted" role="status"><I n="spin" size={18} /> Wczytuję wynik…</p></div>

  const { scan: s } = detail
  const running = isRunning(s.status)
  const failed = !running && s.status !== 'done'
  return (
    <div className="stack-lg">
      <BackLink onBack={onBack} />
      <header>
        <h1>Wynik sprawdzenia: <span className="nowrap">{s.target}</span></h1>
        <p className="muted">Sprawdzenie nr {s.id}{s.created ? `, rozpoczęte ${fmtTime(s.created)}` : ''}</p>
      </header>
      {running && <Progress scan={s} />}
      {failed && <Failed scan={s} onRescan={onRescan} />}
      {s.status === 'done' && <Done detail={detail} onRescan={onRescan} />}
      <ForIT detail={detail} />
    </div>
  )
}

function BackLink({ onBack }) {
  return <p><button className="btn btn-ghost back" onClick={onBack}><I n="back" size={18} />Wróć do listy sprawdzeń</button></p>
}

/* ---------------- w trakcie ---------------- */
function Progress({ scan }) {
  const cur = stepIndex(scan.stage)
  const steps = STEPS.filter((st) => !st.optional || cur >= STEPS.indexOf(st))
  return (
    <section className="panel" aria-labelledby="h-prog">
      <h2 id="h-prog">Sprawdzanie trwa</h2>
      <p>To zwykle kilka minut, czasem dłużej. Możesz zamknąć tę stronę. Sprawdzanie będzie trwać dalej, a wynik znajdziesz na liście sprawdzeń.</p>
      <ol className="progress" aria-live="polite">
        {steps.map((st, i) => {
          const state = cur < 0 ? (i === 0 ? 'now' : 'todo') : i < cur ? 'done' : i === cur ? 'now' : 'todo'
          return (
            <li key={st.id} className={`pstep pstep-${state}`} aria-current={state === 'now' ? 'step' : undefined}>
              <I n={state === 'done' ? 'ok' : state === 'now' ? 'spin' : 'circle'} />
              <span>{st.label}{state === 'done' ? ' (zakończone)' : state === 'now' ? ' (w toku)' : ''}</span>
            </li>
          )
        })}
      </ol>
      {cur < 0 && <p className="muted">{scan.stage ? 'Etap: ' + scan.stage : 'Oczekuję w kolejce na rozpoczęcie.'}</p>}
    </section>
  )
}

function Failed({ scan, onRescan }) {
  return (
    <section className="alert alert-bad block" role="alert">
      <h2><I n="error" />Sprawdzanie nie udało się</h2>
      <p>Program nie zdołał dokończyć sprawdzania. Najczęstsze przyczyny to brak połączenia z internetem albo adres, który nie istnieje. Sprawdź adres i spróbuj ponownie. Jeśli problem wraca, przekaż informatykowi dziennik z sekcji „Dla informatyka” poniżej.</p>
      <button className="btn btn-primary" onClick={onRescan}><I n="again" />Spróbuj ponownie</button>
    </section>
  )
}

/* ---------------- gotowe ---------------- */
function Done({ detail, onRescan }) {
  const { scan: s, counts, findings, diff } = detail
  const v = verdict(s.score, counts)
  const urgent = findings.filter((f) => f.severity === 'critical' || f.severity === 'high')
  const first = findings.slice(0, 3)
  const rest = findings.slice(3)
  const head = {
    bad: { icon: 'shield-alert' }, warn: { icon: 'warning' }, good: { icon: 'shield' },
  }[v.tone]
  return (
    <>
      <section className={`verdict verdict-${v.tone}`} aria-labelledby="h-verdict">
        <I n={head.icon} size={40} />
        <div>
          <h2 id="h-verdict">{v.title}</h2>
          <p>{v.text}</p>
          <p className="verdict-meta">
            {findings.length === 0
              ? 'Nie znaleziono żadnych uwag.'
              : <>Znaleziono {findings.length} {plural(findings.length, 'uwagę', 'uwagi', 'uwag')}
                {urgent.length > 0 && <>, w tym <b>{urgent.length} {plural(urgent.length, 'pilną', 'pilne', 'pilnych')}</b></>}.</>}
            {' '}Ocena ryzyka: <b>{s.score} na 100</b> (im niżej, tym lepiej).
          </p>
          <div className="actions">
            <a className="btn btn-primary btn-lg" href={`/api/scans/${s.id}/report`} target="_blank" rel="noreferrer"><I n="print" />Otwórz raport do wydruku lub PDF</a>
            <button className="btn btn-secondary btn-lg" onClick={onRescan}><I n="again" />Sprawdź ponownie</button>
          </div>
        </div>
      </section>

      {findings.length === 0 ? (
        <section className="panel"><p>Nic nie wymaga naprawy. Warto powtarzać sprawdzenie co jakiś czas, bo stan strony może się zmienić.</p></section>
      ) : (
        <>
          <section aria-labelledby="h-first">
            <h2 id="h-first">Zajmij się tym najpierw</h2>
            <p className="muted">Uwagi są ułożone od najważniejszej. Opis „Co zrobić” możesz przekazać informatykowi bez zmian.</p>
            <ol className="todo">
              {first.map((f, i) => <li key={i}><Finding f={f} detail={detail} open /></li>)}
            </ol>
          </section>
          {rest.length > 0 && (
            <section aria-labelledby="h-rest">
              <h2 id="h-rest">Pozostałe uwagi ({rest.length})</h2>
              <ul className="todo">
                {rest.map((f, i) => <li key={i}><Finding f={f} detail={detail} /></li>)}
              </ul>
            </section>
          )}
        </>
      )}

      <Changes diff={diff} detail={detail} />
      <Trend trend={detail.trend} />
    </>
  )
}

function Finding({ f, detail, open }) {
  const a = detail.assets.find((x) => x.id === f.asset)
  const body = (
    <div className="finding-body">
      <dl className="dl">
        <dt>Co to znaczy</dt><dd>{explain(f)}</dd>
        {f.fix && <><dt>Co zrobić</dt><dd className="fix">{f.fix}</dd></>}
        <dt>Dotyczy</dt><dd className="mono">{a ? assetLabel(a) : f.asset}</dd>
        <dt>Termin</dt><dd>{WHEN[f.severity]}</dd>
      </dl>
      {f.detail && (
        <details className="more"><summary>Szczegóły techniczne</summary><pre>{f.detail}</pre></details>
      )}
    </div>
  )
  return (
    <details className="finding" open={open}>
      <summary>
        <SevBadge sev={f.severity} label={PL[f.severity] || f.severity} />
        <span className="finding-title">{niceTitle(f)}</span>
      </summary>
      {body}
    </details>
  )
}

function Changes({ diff, detail }) {
  const byId = Object.fromEntries(detail.assets.map((a) => [a.id, a]))
  const lab = (id) => (byId[id] ? `${KIND_PL[byId[id].kind] || ''}: ${assetLabel(byId[id])}` : id.replace(/^[a-z]+:/, ''))
  if (!diff) {
    return (
      <section aria-labelledby="h-chg">
        <h2 id="h-chg">Co zmieniło się od ostatniego razu</h2>
        <p className="muted">To pierwsze zakończone sprawdzenie tej strony, więc nie ma jeszcze z czym porównać. Przy następnym sprawdzeniu pokażemy tu, co się poprawiło, a co pogorszyło.</p>
      </section>
    )
  }
  const empty = !diff.new_assets.length && !diff.removed_assets.length && !diff.new_findings.length && !diff.resolved_findings.length
  return (
    <section aria-labelledby="h-chg">
      <h2 id="h-chg">Co zmieniło się od ostatniego razu</h2>
      <p className="muted">Porównanie ze sprawdzeniem nr {diff.against}.</p>
      {empty && <p>Nic się nie zmieniło.</p>}
      {diff.resolved_findings.length > 0 && (
        <div className="chg chg-good"><h3><I n="ok" />Naprawione ({diff.resolved_findings.length})</h3>
          <ul>{diff.resolved_findings.map((x, i) => <li key={i}>{x.title} <span className="muted">({lab(x.asset)})</span></li>)}</ul></div>
      )}
      {diff.new_findings.length > 0 && (
        <div className="chg chg-bad"><h3><I n="warning" />Nowe problemy ({diff.new_findings.length})</h3>
          <ul>{diff.new_findings.map((x, i) => <li key={i}>{x.title} <span className="muted">({lab(x.asset)})</span></li>)}</ul></div>
      )}
      {diff.new_assets.length > 0 && (
        <div className="chg"><h3><I n="info" />Nowe adresy i usługi widoczne z internetu ({diff.new_assets.length})</h3>
          <ul>{diff.new_assets.map((id) => <li key={id}>{lab(id)}</li>)}</ul></div>
      )}
      {diff.removed_assets.length > 0 && (
        <div className="chg"><h3><I n="info" />Przestały być widoczne ({diff.removed_assets.length})</h3>
          <ul>{diff.removed_assets.map((id) => <li key={id}>{lab(id)}</li>)}</ul></div>
      )}
    </section>
  )
}

/* ---------------- dla informatyka ---------------- */
function ForIT({ detail }) {
  const { scan: s, assets } = detail
  const [open, setOpen] = useState(false)
  const [map, setMap] = useState(false)
  return (
    <details className="panel it" onToggle={(e) => setOpen(e.currentTarget.open)}>
      <summary><b>Dla informatyka</b> <span className="muted">(szczegóły techniczne, mapa, dziennik, eksport)</span></summary>
      {open && (
        <div className="stack">
          <p className="actions-inline">
            <a className="btn btn-secondary" href={`/api/scans/${s.id}/export.csv`}><I n="download" size={18} />Pobierz uwagi (CSV, do Excela)</a>
            <a className="btn btn-secondary" href={`/api/scans/${s.id}/export.json`}><I n="download" size={18} />Pobierz komplet danych (JSON)</a>
          </p>

          <h3>Wykryte elementy ({assets.length})</h3>
          {assets.length === 0 ? <p className="muted">Nic nie wykryto.</p> : (
            <div className="tablewrap" tabIndex={0} role="region" aria-label="Wykryte elementy">
              <table className="table">
                <thead><tr><th scope="col">Rodzaj</th><th scope="col">Wartość</th><th scope="col">Szczegóły</th></tr></thead>
                <tbody>
                  {assets.map((a) => (
                    <tr key={a.id}><td>{KIND_PL[a.kind] || a.kind}</td><td className="mono">{a.value}</td><td className="mono muted">{assetInfo(a)}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <h3>Mapa powiązań</h3>
          {!map
            ? <p><button className="btn btn-secondary" onClick={() => setMap(true)}>Pokaż mapę</button></p>
            : <Graph data={detail} running={isRunning(s.status)} />}

          <h3>Dziennik pracy programu</h3>
          <pre className="log" tabIndex={0}>{s.log || 'Brak wpisów.'}</pre>
        </div>
      )}
    </details>
  )
}
