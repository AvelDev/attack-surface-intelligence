import { useEffect, useState } from "react";
import { Lock } from "lucide-react";
import { useI18n } from "../i18n.jsx";

export default function Ticker({ data }) {
  const { t, n, ago } = useI18n();
  const [, force] = useState(0);
  useEffect(() => {
    const h = setInterval(() => force((v) => v + 1), 30000);
    return () => clearInterval(h);
  }, []);
  if (!data) return <footer className="tick" />;
  const tt = data.totals;
  const changes = tt.new + tt.removed + tt.changed + tt.flapping + (tt.offline || 0);
  return (
    <footer className="tick">
      <span><i className="tk tk-ink" aria-hidden="true" />{t("tick.hosts")} <b className="mono">{n(tt.hosts)}</b></span>
      <span><i className="tk tk-ink" aria-hidden="true" />{t("tick.services")} <b className="mono">{n(tt.services)}</b></span>
      <span><i className="tk tk-change" aria-hidden="true" />{t("tick.changes")} <b className="mono">{n(changes)}</b></span>
      <span><i className="tk tk-crit" aria-hidden="true" />{t("tick.critical")} <b className="mono">{n(tt.critical)}</b></span>
      <span>{t("tick.rate")} <b className="mono">{n(data.meta.rate_default)} pps</b></span>
      <span className="tick-sp" />
      {data.meta.encryption && <span><Lock size={12} aria-hidden="true" /> {t("tick.enc")}</span>}
      <span>{t("tick.updated", { when: ago(data.generated) })}</span>
    </footer>
  );
}
