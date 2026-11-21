"""Kontekst jednego skanu: jedyny sposób, w jaki etapy zapisują wyniki (przez repozytorium)."""
import time

from .. import domain
from ..repo import scans as repo


class Ctx:
    def __init__(self, scan_id):
        self.id = scan_id
        self.target, self.opts = repo.target_and_opts(scan_id)
        self._seen_f = set()

    @property
    def deep(self):
        return bool(self.opts.get("deep"))

    def log(self, msg):
        repo.append_log(self.id, time.strftime("%H:%M:%S ") + str(msg)[:600] + "\n")

    def stage(self, name):
        self.log(f"=== {name} ===")
        repo.set_stage(self.id, name)

    def asset(self, kind, value, data=None):
        aid = f"{kind}:{value}"
        repo.upsert_asset(self.id, aid, kind, value, data or {})
        return aid

    def has_asset(self, aid):
        return repo.has_asset(self.id, aid)

    def edge(self, src, dst):
        if src != dst:
            repo.add_edge(self.id, src, dst)

    def finding(self, asset, sev, title, source, detail="", fix=""):
        """Zapisuje ustalenie raz na (zasób, tytuł). Nieznana ważność to błąd programisty - przerywa skan."""
        if not domain.is_severity(sev):
            raise ValueError(f"nieznana ważność ustalenia: {sev!r}")
        key = (asset, title)
        if key in self._seen_f:
            return
        self._seen_f.add(key)
        repo.add_finding(self.id, asset, sev, title, source, detail[:1000], fix)

    def add_tech(self, aid, tech):
        repo.merge_tech(self.id, aid, tech)

    def finish(self, status):
        repo.finish(self.id, status, "zakończony" if status == "done" else "błąd",
                    domain.risk_score(repo.severities(self.id)))
