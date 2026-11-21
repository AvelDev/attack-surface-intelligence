import React, { useCallback, useEffect, useState } from 'react'
import { api, postScan, isRunning } from './api.js'
import { I } from './ui.jsx'
import { Home } from './Home.jsx'
import { Result } from './Result.jsx'
import { Settings } from './Settings.jsx'

/* Adres w pasku (#/sprawdzenie/12) pozwala używać przycisku „wstecz” i zapisać zakładkę. */
const isSettings = () => window.location.hash === '#/ustawienia'
const readHash = () => {
  const m = /^#\/sprawdzenie\/(\d+)$/.exec(window.location.hash)
  return m ? Number(m[1]) : null
}

export default function App() {
  const [scans, setScans] = useState([])
  const [tools, setTools] = useState({})
  const [id, setId] = useState(readHash)
  const [page, setPage] = useState(isSettings() ? 'settings' : 'main')
  const [detail, setDetail] = useState(null)
  const [alerts, setAlerts] = useState(null)
  const [schedules, setSchedules] = useState(null)

  useEffect(() => {
    const h = () => { setId(readHash()); setPage(isSettings() ? 'settings' : 'main') }
    window.addEventListener('hashchange', h)
    return () => window.removeEventListener('hashchange', h)
  }, [])
  const go = useCallback((n) => { window.location.hash = n == null ? '#/' : `#/sprawdzenie/${n}`; window.scrollTo(0, 0) }, [])

  const refreshScans = useCallback(async () => {
    try { setScans(await api('/api/scans')) } catch { /* brak połączenia */ }
  }, [])
  const refreshMonitor = useCallback(async () => {
    try { setAlerts(await api('/api/alerts')); setSchedules(await api('/api/schedules')) } catch { /* brak połączenia */ }
  }, [])
  const markRead = async () => { try { await api('/api/alerts/read', { method: 'POST' }) } catch { /* ignoruj */ } refreshMonitor() }
  useEffect(() => { api('/api/tools').then(setTools).catch(() => {}) }, [])
  const anyRunning = scans.some((s) => isRunning(s.status))
  useEffect(() => {
    refreshScans(); refreshMonitor()
    const t = setInterval(() => { refreshScans(); refreshMonitor() }, anyRunning ? 2500 : 10000)
    return () => clearInterval(t)
  }, [refreshScans, refreshMonitor, anyRunning])

  useEffect(() => {
    if (id == null) { setDetail(null); return }
    let stop = false, timer
    const tick = async () => {
      try {
        const d = await api('/api/scans/' + id)
        if (stop) return
        setDetail({ id, data: d })
        if (isRunning(d.scan.status)) timer = setTimeout(tick, 2000)
      } catch (e) {
        if (stop) return
        setDetail({ id, error: e.message })
      }
    }
    setDetail((d) => (d?.id === id ? d : null))
    tick()
    return () => { stop = true; clearTimeout(timer) }
  }, [id])

  const runScan = async (body) => {
    const { monitor, interval_hours, ...scan } = body
    const r = monitor
      ? await api('/api/schedules', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...scan, interval_hours }) })
      : await postScan(scan)
    await Promise.all([refreshScans(), refreshMonitor()])
    go(monitor ? r.scan_id : r.id)
  }
  const deleteScan = async (sid) => {
    try { await api('/api/scans/' + sid, { method: 'DELETE' }) } catch { /* trwa lub już usunięty */ }
    refreshScans()
  }
  const data = detail && detail.id === id ? detail.data : null
  const error = detail && detail.id === id ? detail.error : null
  const rescan = () => {
    if (!data) return
    let opts = {}
    try { opts = JSON.parse(data.scan.opts || '{}') } catch { /* domyślne */ }
    runScan({ target: data.scan.target, authorized: true, nuclei: !!opts.nuclei, deep: !!opts.deep }).catch(() => {})
  }

  useEffect(() => {
    if (page === 'settings') { document.title = 'Ustawienia'; return }
    document.title = id == null ? 'Sprawdzenie bezpieczeństwa strony' : `Wynik sprawdzenia${data ? ': ' + data.scan.target : ''}`
  }, [id, data, page])

  return (
    <>
      <a className="skip" href="#glowna-tresc">Przejdź do treści</a>
      <header className="site-head">
        <div className="wrap head-in">
          <a className="brand" href="#/" onClick={() => window.scrollTo(0, 0)}>
            <I n="shield" size={28} />
            <span><b>Sprawdzenie bezpieczeństwa strony</b><small>Narzędzie dla pracowników instytucji</small></span>
          </a>
          <a className="btn btn-secondary head-settings" href="#/ustawienia" aria-current={page === 'settings' ? 'page' : undefined}>
            <I n="settings" size={20} />Ustawienia
          </a>
        </div>
      </header>
      <main id="glowna-tresc" className="wrap main" tabIndex={-1}>
        {page === 'settings'
          ? <Settings onBack={() => go(null)} />
          : id == null
          ? <Home scans={scans} tools={tools} alerts={alerts} schedules={schedules} onRun={runScan} onOpen={go}
              onDelete={deleteScan} onReadAlerts={markRead} onMonitorChange={refreshMonitor} />
          : <Result detail={data} error={error} onBack={() => go(null)} onRescan={rescan} />}
      </main>
      <footer className="site-foot">
        <div className="wrap">Program sprawdza wyłącznie to, co jest widoczne z internetu. Nie zmienia niczego na sprawdzanej stronie. Wynik nie zastępuje audytu bezpieczeństwa.</div>
      </footer>
    </>
  )
}
