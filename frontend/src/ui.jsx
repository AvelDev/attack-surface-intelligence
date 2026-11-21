import React from 'react'
import {
  ShieldCheck, ShieldAlert, TriangleAlert, CircleCheck, CircleX, Info, LoaderCircle, ArrowLeft, Printer, RotateCcw,
  Trash2, ChevronRight, Search, Check, Circle, Download, Settings as SettingsIcon,
} from 'lucide-react'

const ICONS = {
  shield: ShieldCheck, 'shield-alert': ShieldAlert, warning: TriangleAlert, ok: CircleCheck, error: CircleX, info: Info,
  spin: LoaderCircle, back: ArrowLeft, print: Printer, again: RotateCcw, trash: Trash2, next: ChevronRight, search: Search,
  check: Check, circle: Circle, download: Download, settings: SettingsIcon,
}

export const I = ({ n, size = 20, className = '' }) => {
  const C = ICONS[n] || Circle
  return <C className={`ico ${n === 'spin' ? 'spin' : ''} ${className}`} size={size} strokeWidth={2} aria-hidden="true" />
}

/** Waga ustalenia: zawsze tekst + kształt, nie tylko kolor. */
export function SevBadge({ sev, label }) {
  const icon = sev === 'critical' || sev === 'high' ? 'error' : sev === 'medium' ? 'warning' : 'info'
  return <span className={`sev sev-${sev}`}><I n={icon} size={16} />{label}</span>
}
