import { useI18n } from "../i18n.jsx";

/** Środek górnego paska przeglądu: filtr zakresu i czas ostatniego przebiegu. */
export default function RangeBar({ ranges, range, onRange, lastPass }) {
  const { t, ago } = useI18n();
  return (
    <>
      <label className="field-inline">
        <span className="sr-only">{t("top.range")}</span>
        <select id="range-select" value={range || ""} onChange={(e) => onRange(e.target.value || null)}>
          <option value="">{t("top.allRanges")} · {ranges.length}</option>
          {ranges.map((r) => (
            <option key={r.id} value={r.id}>{r.name}</option>
          ))}
        </select>
      </label>
      <span className="top-pass">{lastPass ? t("top.lastPass", { when: ago(lastPass) }) : t("top.noPass")}</span>
    </>
  );
}
