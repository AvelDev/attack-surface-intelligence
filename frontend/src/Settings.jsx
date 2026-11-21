import React, { useCallback, useEffect, useState } from 'react'
import { I } from './ui.jsx'
import { api } from './api.js'

/* Co daje każde narzędzie i czym jest zastępowane, gdy go brakuje. */
const TOOL_INFO = {
  subfinder: ['Subdomeny (pasywnie)', 'Certificate Transparency (crt.sh)'],
  amass: ['Subdomeny (szersze źródła)', 'HackerTarget i Anubis'],
  assetfinder: ['Subdomeny (szybkie źródła)', 'HackerTarget i Anubis'],
  dnsx: ['Rozwiązywanie nazw DNS', 'zapytania DNS w Pythonie'],
  dnsrecon: ['Transfer strefy DNS (AXFR)', 'własna implementacja AXFR'],
  naabu: ['Szybki skan portów', 'nmap, a potem skan w Pythonie'],
  nmap: ['Skan portów i wersje usług', 'skan w Pythonie'],
  httpx: ['Sondowanie usług WWW', 'zapytania HTTP w Pythonie'],
  sslyze: ['Audyt szyfrowania (TLS)', 'testssl.sh, a potem prosta kontrola TLS 1.0/1.1'],
  testssl: ['Audyt szyfrowania (TLS)', 'sslyze lub prosta kontrola TLS 1.0/1.1'],
  wafw00f: ['Wykrywanie zapory aplikacyjnej (WAF)', 'rozpoznawanie po nagłówkach'],
  whatweb: ['Rozpoznawanie technologii strony', 'nagłówki i znacznik generator'],
  gau: ['Historyczne adresy URL', 'archiwum Wayback Machine (CDX)'],
  waybackurls: ['Historyczne adresy URL', 'archiwum Wayback Machine (CDX)'],
  katana: ['Crawling strony (tylko tryb dokładny)', 'brak, pomijane'],
  nuclei: ['Szablony znanych luk (opcjonalnie)', 'brak, pomijane'],
}

export function Settings({ onBack }) {
  const [items, setItems] = useState(null)
  const [tools, setTools] = useState(null)
  const [err, setErr] = useState('')
  const load = useCallback(async () => {
    try { setItems(await api('/api/settings')); setTools(await api('/api/tools')) } catch (e) { setErr(e.message) }
  }, [])
  useEffect(() => { load() }, [load])

  return (
    <div className="stack-lg">
      <p><button className="btn btn-ghost back" onClick={onBack}><I n="back" size={18} />Wróć do listy sprawdzeń</button></p>
      <header>
        <h1>Ustawienia</h1>
        <p className="lead">Tu zapisujesz klucze dostępu do zewnętrznych baz danych. Klucze są opcjonalne: bez nich program działa, ale korzysta z ubogich lub darmowych źródeł.</p>
      </header>
      {err && <div className="alert alert-bad" role="alert"><I n="error" /><span>{err}</span></div>}

      <section aria-labelledby="h-keys">
        <h2 id="h-keys">Klucze dostępu (API)</h2>
        <div className="alert alert-info"><I n="info" /><span>Klucz zapisuje się na serwerze i po zapisaniu nie jest już nigdzie wyświetlany, widać tylko gwiazdki. Aby go zmienić, wpisz nowy. Nie udostępniaj programu osobom, którym nie ufasz: każdy, kto ma do niego dostęp, może użyć zapisanych kluczy.</span></div>
        {!items ? <p className="muted" role="status"><I n="spin" size={18} /> Wczytuję…</p> : (
          <ul className="keys">
            {items.map((it) => <KeyRow key={it.key} it={it} onChange={load} />)}
          </ul>
        )}
      </section>

      <section aria-labelledby="h-tools">
        <h2 id="h-tools">Narzędzia używane przez program</h2>
        <p className="muted">Zainstalowane narzędzia dają dokładniejsze wyniki. Gdy brakuje narzędzia, program używa zamiennika podanego w ostatniej kolumnie. Instalacja: skrypt <code>scripts/install_tools.sh</code> lub obraz Docker.</p>
        {tools && (
          <div className="tablewrap" tabIndex={0} role="region" aria-label="Narzędzia">
            <table className="table">
              <thead><tr><th scope="col">Narzędzie</th><th scope="col">Do czego służy</th><th scope="col">Stan</th><th scope="col">Zamiennik, gdy brak</th></tr></thead>
              <tbody>
                {Object.entries(tools).map(([n, v]) => (
                  <tr key={n}>
                    <td className="mono">{n}</td>
                    <td>{(TOOL_INFO[n] || ['', ''])[0]}</td>
                    <td>{v.installed ? <span className="chip chip-good"><I n="ok" size={16} />Jest</span> : <span className="chip chip-warn"><I n="warning" size={16} />Brak</span>}</td>
                    <td className="muted">{v.installed ? '' : (TOOL_INFO[n] || ['', ''])[1]}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}

function KeyRow({ it, onChange }) {
  const [val, setVal] = useState('')
  const [msg, setMsg] = useState(null)
  const [ask, setAsk] = useState(false)
  const [busy, setBusy] = useState(false)
  const id = `k-${it.key}`
  const fromEnv = it.source === 'env'

  const save = async (e) => {
    e.preventDefault()
    if (!val.trim()) { setMsg({ bad: true, text: 'Wpisz klucz.' }); return }
    setBusy(true); setMsg(null)
    try {
      await api(`/api/settings/${it.key}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ value: val }) })
      setVal(''); setMsg({ text: 'Zapisano.' }); await onChange()
    } catch (ex) { setMsg({ bad: true, text: ex.message }) }
    finally { setBusy(false) }
  }
  const remove = async () => {
    setAsk(false)
    try { await api(`/api/settings/${it.key}`, { method: 'DELETE' }); setMsg({ text: 'Klucz usunięty.' }); await onChange() }
    catch (ex) { setMsg({ bad: true, text: ex.message }) }
  }

  return (
    <li className="panel key-row">
      <form onSubmit={save} noValidate>
        <div className="key-head">
          <label htmlFor={id} className="label">{it.label}</label>
          {it.set
            ? <span className="chip chip-good"><I n="ok" size={16} />Zapisany: <span className="mono" aria-label="ukryty">{it.masked}</span></span>
            : <span className="chip">Nie ustawiony</span>}
        </div>
        <p className="help" id={`${id}-h`}>{it.help} <a href={it.url} target="_blank" rel="noreferrer">Skąd wziąć klucz{it.free ? ' (darmowy)' : ''}</a>.</p>
        {fromEnv ? (
          <p className="muted">Ten klucz jest ustawiony zmienną środowiskową na serwerze i nie można go zmienić z poziomu strony.</p>
        ) : (
          <div className="key-input">
            <input id={id} name={id} type="password" className="input" value={val} onChange={(e) => setVal(e.target.value)}
              placeholder={it.set ? 'Wpisz nowy klucz, aby zastąpić zapisany' : 'Wklej klucz'}
              autoComplete="new-password" spellCheck="false" aria-describedby={`${id}-h`} />
            <button className="btn btn-primary" type="submit" disabled={busy || !val}>{busy ? 'Zapisuję…' : 'Zapisz'}</button>
            {it.set && (ask ? (
              <span className="confirm" role="group" aria-label={`Potwierdź usunięcie klucza ${it.label}`}>
                <button type="button" className="btn btn-danger" onClick={remove}>Tak, usuń klucz</button>
                <button type="button" className="btn btn-secondary" onClick={() => setAsk(false)}>Anuluj</button>
              </span>
            ) : <button type="button" className="btn btn-ghost" onClick={() => setAsk(true)} aria-label={`Usuń klucz ${it.label}`}><I n="trash" size={18} />Usuń</button>)}
          </div>
        )}
        {msg && <p className={msg.bad ? 'form-msg bad' : 'form-msg'} role={msg.bad ? 'alert' : 'status'}>{msg.text}</p>}
      </form>
    </li>
  )
}
