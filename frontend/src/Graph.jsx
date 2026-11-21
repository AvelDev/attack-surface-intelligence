import React, { useEffect, useRef } from 'react'
import { Network, DataSet } from 'vis-network/standalone'
import { SEVS, KIND_COLOR, KIND_PL, PL, assetLabel } from './api.js'

const SEV_COLOR = { critical: '#8f1620', high: '#b3380a', medium: '#9a6a00', low: '#0b4f9e', info: '#4a5565' }
const FONT = 'Segoe UI, system-ui, Arial, sans-serif'

function worstBy(findings) {
  const w = {}
  findings.forEach((f) => {
    if (w[f.asset] === undefined || SEVS.indexOf(f.severity) < SEVS.indexOf(w[f.asset])) w[f.asset] = f.severity
  })
  return w
}

/** Mapa powiązań (sekcja „Dla informatyka”): montowana dopiero na żądanie. */
export function Graph({ data, running }) {
  const box = useRef(null)
  const net = useRef(null)
  const nodes = useRef(null)
  const edges = useRef(null)

  useEffect(() => {
    nodes.current = new DataSet()
    edges.current = new DataSet()
    net.current = new Network(box.current, { nodes: nodes.current, edges: edges.current }, {
      physics: { stabilization: { iterations: 200, fit: true }, barnesHut: { springLength: 95, gravitationalConstant: -3500, springConstant: 0.03 } },
      nodes: { font: { color: '#1a2433', size: 14, face: FONT }, shadow: false },
      edges: { color: { color: '#9aa6b6', highlight: '#0b4f9e', hover: '#5c6b80' }, smooth: false, width: 1.5 },
      interaction: { hover: true, tooltipDelay: 200, zoomSpeed: 0.6 },
    })
    net.current.on('stabilized', () => net.current.setOptions({ physics: { enabled: false } }))
    return () => { net.current.destroy(); net.current = null }
  }, [])

  useEffect(() => {
    if (!net.current) return
    const worst = worstBy(data.findings)
    const ns = data.assets.map((a) => ({
      id: a.id, label: assetLabel(a),
      title: `${KIND_PL[a.kind] || a.kind}: ${a.value}${worst[a.id] ? ` (najpoważniejsza uwaga: ${PL[worst[a.id]]})` : ''}`,
      color: { background: KIND_COLOR[a.kind] || '#5c6b80', border: worst[a.id] ? SEV_COLOR[worst[a.id]] : '#ffffff' },
      borderWidth: worst[a.id] ? 4 : 1,
      shape: a.kind === 'port' ? 'box' : 'dot', size: a.kind === 'domain' ? 22 : 13,
      font: a.kind === 'port' ? { color: '#ffffff', size: 13, face: FONT } : undefined,
    }))
    const es = data.edges.map((e) => ({ id: e.src + '>' + e.dst, from: e.src, to: e.dst }))
    const have = new Set(nodes.current.getIds())
    const grew = ns.some((n) => !have.has(n.id))
    nodes.current.update(ns)
    nodes.current.remove([...have].filter((id) => !ns.some((n) => n.id === id)))
    const haveE = new Set(edges.current.getIds())
    edges.current.update(es)
    edges.current.remove([...haveE].filter((id) => !es.some((e) => e.id === id)))
    if (grew) net.current.setOptions({ physics: { enabled: true } })
  }, [data.assets, data.edges, data.findings])

  return (
    <div className="graph-wrap">
      <div className="vis" ref={box} role="img" aria-label="Mapa powiązań między wykrytymi adresami i usługami. Te same dane są w tabeli powyżej." />
      {data.assets.length === 0 && <div className="graph-empty">{running ? 'Zbieranie danych…' : 'Nic nie wykryto.'}</div>}
      <ul className="legend" aria-label="Legenda mapy">
        {Object.entries(KIND_COLOR).map(([k, c]) => (<li key={k}><span className="dot" style={{ background: c }} />{KIND_PL[k]}</li>))}
        <li className="muted">Gruba obwódka oznacza element z uwagą (kolor = waga).</li>
      </ul>
    </div>
  )
}
