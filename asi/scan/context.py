"""Kontekst jednego skanu: jedyny sposób, w jaki etapy zapisują wyniki (przez repozytorium).

Wątek pipeline'u pisze przez trwałe połączenie (repo.scans.Writer). Metody wołane też z wątków roboczych
(log, stage, check_time_limit) używają krótkich połączeń z repozytorium - połączenie SQLite nie jest współdzielone
między wątkami.
"""
import time

from .. import domain
from ..repo import scans as repo


class ScanStopped(Exception):
    """Operator zażądał zatrzymania skanu (POST /api/scans/{id}/stop)."""


class WindowExceeded(TimeoutError):
    """Skończyło się okno czasowe jednego posiedzenia - skan zostaje wstrzymany i da się go wznowić z punktu kontrolnego."""


class Ctx:
    def __init__(self, scan_id):
        self.id = scan_id
        self.target, self.opts, self.created, self.targets = repo.run_info(scan_id)
        # time_window_mins to budżet na JEDNO posiedzenie, nie deadline od "created" - inaczej skan wznowiony długo po
        # pierwszym przebiegu miałby okno z definicji przekroczone i od razu wstrzymałby się drugi raz bez żadnej pracy.
        # Każdy nowy Ctx (świeży skan albo wznowienie) dostaje pełne okno od nowa.
        self._session_start = time.time()
        self._seen_f = set()
        self.db = repo.Writer(scan_id)

    def close(self):
        self.db.close()

    @property
    def deep(self):
        return bool(self.opts.get("deep"))

    def log(self, msg):
        repo.append_log(self.id, time.strftime("%H:%M:%S ") + str(msg)[:600] + "\n")

    def stage(self, name):
        # Granica etapu to bezpieczny punkt na zatrzymanie (ręczne lub okno czasowe) - inaczej długie etapy poza skanem
        # portów nie reagowałyby na "Wstrzymaj".
        self.check_time_limit()
        self.log(f"=== {name} ===")
        repo.set_stage(self.id, name)

    def check_time_limit(self):
        """Rzuca ScanStopped lub WindowExceeded. Bezpieczne z wątków roboczych (nie używa połączenia Writera)."""
        if repo.stop_requested(self.id):
            raise ScanStopped("Skan zatrzymany ręcznie przez operatora")
        limit_m = self.opts.get("time_window_mins")
        if limit_m and (time.time() - self._session_start) > int(limit_m) * 60:
            raise WindowExceeded(f"Przekroczono okno czasowe skanu ({limit_m} min)")

    def asset(self, kind, value, data=None):
        aid = f"{kind}:{value}"
        self.db.upsert_asset(aid, kind, value, data or {})
        return aid

    def has_asset(self, aid):
        return self.db.has_asset(aid)

    def edge(self, src, dst):
        if src != dst:
            self.db.add_edge(src, dst)

    def finding(self, asset, sev, title, source, detail="", fix=""):
        """Zapisuje ustalenie raz na (zasób, tytuł). Nieznana ważność to błąd programisty - przerywa skan.
        Trwała decyzja operatora (finding_overrides) nadpisuje ważność i zalecenie albo oznacza fałszywy alarm."""
        if not domain.is_severity(sev):
            raise ValueError(f"nieznana ważność ustalenia: {sev!r}")
        key = (asset, title)
        if key in self._seen_f:
            return
        self._seen_f.add(key)
        ov = self.db.override_for(asset, title)
        if ov:
            sev = ov["severity"]
            if ov["fix"]:
                fix = ov["fix"]
            if ov["false_positive"]:
                sev = "info"
                title = f"[False Positive] {title}"
        self.db.add_finding(asset, sev, title, source, detail[:1000], fix)

    def add_tech(self, aid, tech):
        self.db.merge_tech(aid, tech)

    def hosts_total(self, n):
        self.db.set_hosts_total(n)

    def hosts_progress(self, done):
        self.db.set_hosts_done(done)

    # ---------- punkt wznowienia ----------
    def load_checkpoint(self):
        """None, jeśli skan nie ma stanu do wznowienia (pierwszy przebieg albo poprzedni skończył się bez przekroczenia okna)."""
        return self.db.load_checkpoint()

    def save_checkpoint(self, **fields):
        """Scalanie pól z już zapisanymi. Wołane tylko z wątku pipeline'u (brak współbieżnych pisarzy, więc bez locka)."""
        cp = self.load_checkpoint() or {}
        cp.update(fields)
        self.db.save_checkpoint(cp)

    def clear_checkpoint(self):
        self.db.clear_checkpoint()

    def finish(self, status):
        stage_txt = {"done": "zakończony", "paused_window": "okno czasowe (wstrzymany)",
                     "stopped": "zatrzymany ręcznie"}.get(status, "błąd")
        score = domain.risk_score(self.db.severities(), self.db.host_count())
        self.db.finish(status, stage_txt, score, time.time() - self.created)
        if status != "paused_window":
            # Jedyny status, dla którego punkt wznowienia ma dalej służyć - w każdym innym (done/stopped/failed)
            # kolejne uruchomienie tego scan_id musi zacząć pipeline od zera.
            self.db.clear_checkpoint()
