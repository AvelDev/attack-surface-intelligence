import { useEffect, useState } from "react";
import { ArrowUpRight } from "lucide-react";
import { api, can } from "../api.js";
import { useI18n } from "../i18n.jsx";
import { href } from "../router.js";
import Frame from "../components/Frame.jsx";
import Page from "../components/Page.jsx";
import { FindingsTable, FindingDialog } from "../components/Findings.jsx";
import { Empty, LoadState, ScanState, useResource, useToast } from "../components/ui.jsx";

/** Ustalenia jednego przebiegu z edycją triage; domyślnie najnowszy skan, który coś znalazł. */
export default function FindingsScreen({ user, shell, onAuthLost }) {
  const { t, n, date } = useI18n();
  const { toast, flash, clear } = useToast();
  const scans = useResource(api.scans, onAuthLost, []);
  const [pick, setPick] = useState(null);
  const [editing, setEditing] = useState(null);
  const list = scans.data || [];

  useEffect(() => {
    if (pick || !list.length) return;
    setPick((list.find((s) => s.findings > 0) || list[0]).id);
  }, [list, pick]);

  const detail = useResource(() => (pick ? api.scan(pick) : Promise.resolve(null)), onAuthLost, [pick]);
  const d = detail.data;
  const cur = list.find((s) => s.id === pick);

  return (
    <Page shell={shell} title={t("nav.findings")} refreshing={scans.loading || detail.loading}
          onRefresh={() => { scans.load(); detail.load(); }} toast={toast} onToastClose={clear} className="single">
      <Frame tag="A" id="f-mod" className="f-mod" title={t("f.title")}
             meta={d ? t("f.meta", { n: n(d.findings.length) }) : null}
             actions={cur && (
               <a className="btn btn-sm" href={href("scans", cur.id)}>{t("c.openScan")} <ArrowUpRight size={13} aria-hidden="true" /></a>
             )}>
        {!scans.data ? <LoadState error={scans.error} onRetry={scans.load} /> : !list.length ? (
          <Empty title={t("s.none")}><p className="quiet">{t("f.noneHint")}</p><a className="btn" href={href("scans")}>{t("nav.ranges")}</a></Empty>
        ) : (
          <>
            <div className="f-pick">
              <label className="field-inline">
                <span className="f-pick-label">{t("f.pass")}</span>
                <select value={pick || ""} onChange={(e) => setPick(+e.target.value)}>
                  {list.map((s) => (
                    <option key={s.id} value={s.id}>#{s.id} · {s.target} · {date(s.created)} · {t("s.findingsN", { n: s.findings })}</option>
                  ))}
                </select>
              </label>
              {cur && <ScanState status={cur.status} />}
            </div>
            {!d ? <LoadState error={detail.error} onRetry={detail.load} rows={6} /> : (
              <FindingsTable key={pick} findings={d.findings} canEdit={can(user, "read_modify")} onEdit={setEditing} />
            )}
          </>
        )}
      </Frame>
      {editing && <FindingDialog finding={editing} onClose={() => setEditing(null)} onSaved={detail.load} onAuthLost={onAuthLost} flash={flash} />}
    </Page>
  );
}
