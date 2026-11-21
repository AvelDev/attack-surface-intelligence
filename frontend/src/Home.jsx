import React, { useRef, useState, useEffect } from 'react'
import { I } from './ui.jsx'
import { isRunning, verdict, fmtShort, plural } from './api.js'
import { Alerts, Monitored } from './Monitor.jsx'

export function Home({ scans, tools, alerts, schedules, onRun, onOpen, onDelete, onReadAlerts, onMonitorChange }) {
  const [target, setTarget] = useState('')
  const [auth, setAuth] = useState(false)
  const [nuclei, setNuclei] = useState(false)
  const [deep, setDeep] = useState(false)
  const [monitor, setMonitor] = useState(false)
  const [every, setEvery] = useState(168)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const input = useRef(null)
  useEffect(() => { input.current?.focus() }, [])

  const submit = async (e) => {
    e.preventDefault()
    if (!target.trim()) { setErr('Wpisz adres strony internetowej, np. www.urzad.gov.pl.'); input.current?.focus(); return }
    if (!auth) { setErr('Zaznacz oświadczenie poniżej. Bez niego nie możemy rozpocząć sprawdzania.'); return }
    setErr(''); setBusy(true)
    try { await onRun({ target, authorized: auth, nuclei, deep, monitor, interval_hours: every }) }
    catch (ex) { setErr(ex.message) }
    finally { setBusy(false) }
  }

  return (
    <div className="stack-lg">
      <section aria-labelledby="h-start">
        <h1 id="h-start">Sprawdź, czy strona Twojej instytucji jest bezpieczna</h1>
        <p className="lead">Wpisz adres strony internetowej. Program sprawdzi, co jest widoczne z internetu, i poda prostą ocenę oraz listę rzeczy do naprawy. Całość trwa zwykle kilka minut. Nie musisz znać się na informatyce.</p>

        <form className="panel form" onSubmit={submit} noValidate>
          <div className="field">
            <label htmlFor="adres" className="label">Adres strony internetowej</label>
            <p className="help" id="adres-help">Na przykład: www.urzad.gov.pl. Możesz też wkleić cały adres skopiowany z przeglądarki.</p>
            <input id="adres" ref={input} type="text" className="input" value={target} onChange={(e) => setTarget(e.target.value)}
              autoComplete="off" spellCheck="false" inputMode="url" aria-describedby="adres-help" />
          </div>

          <div className="consent">
            <input id="zgoda" type="checkbox" checked={auth} onChange={(e) => setAuth(e.target.checked)} />
            <label htmlFor="zgoda">
              Oświadczam, że ta strona należy do mojej instytucji albo mam zgodę jej właściciela na sprawdzenie.
              <span className="help block">Sprawdzanie cudzych stron bez zgody może być niezgodne z prawem.</span>
            </label>
          </div>

          <div className="consent">
            <input id="monitor" type="checkbox" checked={monitor} onChange={(e) => setMonitor(e.target.checked)} />
            <label htmlFor="monitor">
              Sprawdzaj tę stronę automatycznie i powiadom mnie, gdy coś się pogorszy
              <span className="help block">Program sam powtórzy sprawdzenie i porówna wynik z poprzednim. Zgoda powyżej obejmuje także te powtórzenia.</span>
            </label>
          </div>
          {monitor && (
            <div className="inline-field">
              <label htmlFor="co-ile" className="label">Jak często?</label>
              <select id="co-ile" className="select" value={every} onChange={(e) => setEvery(Number(e.target.value))}>
                <option value={24}>Codziennie</option><option value={168}>Co tydzień</option><option value={720}>Co miesiąc</option>
              </select>
            </div>
          )}

          <details className="more">
            <summary>Ustawienia dodatkowe (dla informatyka)</summary>
            <div className="consent">
              <input id="nuclei" type="checkbox" checked={nuclei} onChange={(e) => setNuclei(e.target.checked)} disabled={tools.nuclei && !tools.nuclei.installed} />
              <label htmlFor="nuclei">
                Dokładniejsze sprawdzenie: wyszukiwanie znanych luk w oprogramowaniu
                <span className="help block">Trwa dłużej i generuje więcej ruchu na stronie. Zalecane tylko po uzgodnieniu z administratorem.
                  {tools.nuclei && !tools.nuclei.installed ? ' Niedostępne: brak zainstalowanego narzędzia nuclei.' : ''}</span>
              </label>
            </div>
            <div className="consent">
              <input id="deep" type="checkbox" checked={deep} onChange={(e) => setDeep(e.target.checked)} />
              <label htmlFor="deep">
                Tryb dokładny: przeglądanie stron i szersze wyszukiwanie adresów
                <span className="help block">Program przechodzi po stronie jak robot, szuka dodatkowych adresów i dokładniej bada szyfrowanie. Skan trwa znacznie dłużej i generuje więcej ruchu. Używaj tylko po uzgodnieniu z administratorem strony.</span>
              </label>
            </div>
          </details>

          {err && <div className="alert alert-bad" role="alert"><I n="error" /><span>{err}</span></div>}

          <div className="actions">
            <button className="btn btn-primary btn-lg" type="submit" disabled={busy}>
              <I n={busy ? 'spin' : 'search'} />{busy ? 'Uruchamiam sprawdzanie…' : 'Sprawdź stronę'}
            </button>
          </div>
          <p className="help">Chcesz tylko wypróbować program? Użyj strony testowej{' '}
            <button type="button" className="linklike" onClick={() => setTarget('scanme.nmap.org')}>scanme.nmap.org</button>, której sprawdzanie jest dozwolone.</p>
        </form>
      </section>

      <Alerts alerts={alerts} onOpen={onOpen} onRead={onReadAlerts} />
      <Monitored schedules={schedules} onChange={onMonitorChange} onOpen={onOpen} />

      <section aria-labelledby="h-jak">
        <h2 id="h-jak">Jak to działa</h2>
        <ol className="steps-list">
          <li><b>Wpisujesz adres strony.</b> Potwierdzasz, że masz prawo ją sprawdzić.</li>
          <li><b>Program sprawdza stronę.</b> Szuka otwartych drzwi, które nie powinny być widoczne z internetu. Niczego nie zmienia ani nie psuje.</li>
          <li><b>Dostajesz wynik i raport.</b> Ocenę w jednym zdaniu, listę spraw do załatwienia oraz raport, który przekażesz informatykowi lub przełożonemu.</li>
        </ol>
      </section>

      <History scans={scans} onOpen={onOpen} onDelete={onDelete} />
    </div>
  )
}

function History({ scans, onOpen, onDelete }) {
  const [ask, setAsk] = useState(null)
  return (
    <section aria-labelledby="h-hist">
      <h2 id="h-hist">Wcześniejsze sprawdzenia</h2>
      {scans.length === 0 ? (
        <p className="muted">Nie wykonano jeszcze żadnego sprawdzenia. Gdy je wykonasz, pojawi się tutaj.</p>
      ) : (
        <ul className="hist">
          {scans.map((s) => {
            const running = isRunning(s.status)
            const failed = !running && s.status !== 'done'
            const v = verdict(s.score, {})
            return (
              <li key={s.id} className="hist-row">
                <div className="hist-main">
                  <button className="hist-link" onClick={() => onOpen(s.id)}>{s.target}</button>
                  <span className="muted">{fmtShort(s.created)}</span>
                </div>
                <div className="hist-state">
                  {running && <span className="chip chip-run"><I n="spin" size={16} />W trakcie</span>}
                  {failed && <span className="chip chip-bad"><I n="error" size={16} />Nie udało się</span>}
                  {!running && !failed && <span className={`chip chip-${v.tone}`}>{v.title}</span>}
                  {!running && !failed && <span className="muted">{s.findings} {plural(s.findings, 'uwaga', 'uwagi', 'uwag')}</span>}
                </div>
                <div className="hist-act">
                  <button className="btn btn-secondary" onClick={() => onOpen(s.id)}>{running ? 'Zobacz postęp' : 'Otwórz wynik'}</button>
                  {!running && (ask === s.id ? (
                    <span className="confirm" role="group" aria-label={`Potwierdź usunięcie ${s.target}`}>
                      <span>Usunąć na stałe?</span>
                      <button className="btn btn-danger" onClick={() => { setAsk(null); onDelete(s.id) }}>Tak, usuń</button>
                      <button className="btn btn-secondary" onClick={() => setAsk(null)}>Anuluj</button>
                    </span>
                  ) : (
                    <button className="btn btn-ghost" onClick={() => setAsk(s.id)} aria-label={`Usuń sprawdzenie ${s.target} z dnia ${fmtShort(s.created)}`}><I n="trash" size={18} />Usuń</button>
                  ))}
                </div>
              </li>
            )
          })}
        </ul>
      )}
    </section>
  )
}
