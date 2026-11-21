import { useEffect, useRef } from "react";
import { useI18n } from "../i18n.jsx";

const KEYS = [
  [["↑", "↓"], "keys.nav"], [["J", "K"], "keys.nav"], [["X"], "keys.select"], [["1"], "keys.ok"],
  [["2"], "keys.accept"], [["3"], "keys.fp"], [["0"], "keys.reopen"], [["E"], "keys.export"],
  [["R"], "keys.refresh"], [["/"], "keys.range"], [["?"], "keys.help"],
];

export default function Shortcuts({ onClose }) {
  const { t } = useI18n();
  const ref = useRef(null);
  useEffect(() => {
    const d = ref.current;
    d.showModal();
    const onCancel = (e) => { e.preventDefault(); onClose(); };
    d.addEventListener("cancel", onCancel);
    return () => d.removeEventListener("cancel", onCancel);
  }, [onClose]);
  return (
    <dialog ref={ref} className="mod keys" aria-labelledby="keys-h" onClick={(e) => e.target === ref.current && onClose()}>
      <h2 className="mod-title" id="keys-h">{t("keys.title")}</h2>
      <dl>
        {KEYS.map(([ks, label], i) => (
          <div key={i}>
            <dt>{ks.map((k) => <kbd key={k}>{k}</kbd>)}</dt>
            <dd>{t(label)}</dd>
          </div>
        ))}
      </dl>
      <button type="button" className="btn" onClick={onClose} autoFocus>{t("keys.close")}</button>
    </dialog>
  );
}
