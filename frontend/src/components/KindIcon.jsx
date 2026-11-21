import { Plus, Minus, Replace, ArrowUpDown, CircleOff, TriangleAlert, ShieldAlert } from "lucide-react";

const ICONS = {
  new: Plus,
  removed: Minus,
  changed: Replace,
  flapping: ArrowUpDown,
  offline: CircleOff,
  critical: TriangleAlert,
  finding: ShieldAlert,
};

/** Kształt zawsze towarzyszy kolorowi (bezpieczne dla daltonistów): stan czyta się z ikony. */
export default function KindIcon({ kind, severity, size = 15 }) {
  const crit = severity === "critical" || kind === "critical";
  const Icon = crit && kind === "finding" ? TriangleAlert : ICONS[kind] || ShieldAlert;
  const tone = crit ? "crit" : ["new", "changed", "flapping", "removed", "offline"].includes(kind) ? "change" : "ink";
  return <Icon className={`kicon kicon-${tone}`} size={size} strokeWidth={1.75} aria-hidden="true" />;
}
