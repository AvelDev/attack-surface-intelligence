"""Syntetyczne dane demonstracyjne dla ekranu Przegląd (NIE są wynikiem prawdziwego skanu).

Odtwarza scenariusze z labu AGH (lab/): usługa HTTP na 8787 znika i wraca (quickstart.sh),
pojawia się DVWA, Gitea zmienia wersję - plus duży syntetyczny zakres /20 i zakres domen
przerwany przez okno czasowe. Zapisuje do osobnej bazy, żeby nie mieszać z prawdziwymi skanami:

    ASI_DB=data/demo.db python scripts/seed_demo.py
    ASI_DB=data/demo.db uvicorn asi.main:app --port 8000
"""
import hashlib
import json
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from asi import config, crypto, db  # noqa: E402

DB_PATH = config.load().db_path

DAY = 86400
rnd = random.Random(20261121)


def add_scan(c, target, targets, created, dur, status="done", opts=None, hosts_total=None):
    thash = hashlib.sha256("\n".join(sorted(targets)).encode()).hexdigest()
    stage = {"done": "zakończony", "paused_window": "okno czasowe (wstrzymany)"}.get(status, status)
    sid = c.execute(
        "INSERT INTO scans(target,target_hash,opts,status,stage,score,hosts_total,hosts_done,duration_s,created,finished,log) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (target, thash, json.dumps(opts or {}), status, stage, 0, hosts_total or len(targets),
         hosts_total or len(targets), dur, created, created + dur,
         crypto.enc("dane demonstracyjne (syntetyczne)\n"))).lastrowid
    c.executemany("INSERT OR IGNORE INTO scan_targets VALUES(?,?)", [(sid, t) for t in targets[:5000]])
    return sid, thash


def asset(c, sid, kind, value, data=None):
    c.execute("INSERT OR REPLACE INTO assets VALUES(?,?,?,?,?)",
              (sid, f"{kind}:{value}", kind, value, crypto.enc(json.dumps(data or {}))))
    return f"{kind}:{value}"


def finding(c, sid, aid, sev, title, detail, fix, source="builtin"):
    c.execute("INSERT INTO findings VALUES(?,?,?,?,?,?,?)", (sid, aid, sev, title, source, crypto.enc(detail), fix))


LAB_PORTS = {
    21: ("ftp", "vsftpd 3.0.3", None),
    2223: ("ssh", "OpenSSH 8.4p1", None),
    3001: ("http", "Gitea 1.21.11", ("Gitea: Git with a cup of tea", ["Gitea", "Go"])),
    5673: ("amqp", "RabbitMQ 3.13", None),
    8088: ("http", "Apache 2.4.10", ("Witaj w WordPress", ["WordPress 4.7", "PHP/5.6.30", "Apache/2.4.10"])),
    8089: ("http", "PHP 8.2", ("Login - Adminer", ["Adminer", "PHP"])),
    8787: ("http", "nginx 1.27", ("Welcome to nginx!", ["Nginx"])),
    8888: ("http", "gunicorn 19.9", ("httpbin.org", ["Gunicorn", "Python"])),
    15432: ("postgres", "PostgreSQL 16", None),
    15673: ("http", "RabbitMQ Management", ("RabbitMQ Management", ["RabbitMQ"])),
}


def seed_lab(c, now):
    target = ["127.0.0.1"]
    passes = 7
    for i in range(passes):
        t = now - (passes - 1 - i) * DAY + 3600 * 2
        sid, thash = add_scan(c, "127.0.0.1 (lab AGH)", target, t, 140 + rnd.randint(0, 60),
                              opts={"time_window_mins": 30})
        ip = "127.0.0.1"
        asset(c, sid, "ip", ip)
        ports = dict(LAB_PORTS)
        if i in (2, 4):          # quickstart.sh change: 8787 zatrzymany
            ports.pop(8787)
        if i == passes - 1:      # nowa usługa w ostatnim przebiegu
            ports[8090] = ("http", "Apache 2.4.25", ("Login :: Damn Vulnerable Web Application (DVWA)",
                                                     ["DVWA", "PHP/7.0.30", "Apache/2.4.25"]))
            ports[3001] = ("http", "Gitea 1.22.3", ("Gitea: Git with a cup of tea", ["Gitea", "Go"]))
        for p, (svc, ver, web) in ports.items():
            pid = asset(c, sid, "port", f"{ip}:{p}", {"port": p, "service": svc, "version": ver})
            if web:
                title, tech = web
                wid = asset(c, sid, "web", f"http://{ip}:{p}",
                            {"url": f"http://{ip}:{p}", "status": 200, "title": title,
                             "server": ver, "tech": tech})
                finding(c, sid, wid, "medium", "Usługa dostępna po nieszyfrowanym HTTP bez przekierowania",
                        f"http://{ip}:{p} -> 200", "Wymuś przekierowanie 301 na HTTPS i włącz HSTS.")
        finding(c, sid, f"port:{ip}:21", "high", "FTP bez szyfrowania wystawiony",
                f"{ip}:21 ftp vsftpd 3.0.3", "Wyłącz FTP albo zastąp SFTP/FTPS.")
        finding(c, sid, f"port:{ip}:15432", "high", "Baza danych dostępna z sieci",
                f"{ip}:15432 postgres", "Ogranicz dostęp do bazy firewallem do sieci aplikacji.")
        finding(c, sid, f"web:http://{ip}:8088", "high", "Przestarzały CMS: WordPress 4.7",
                "generator: WordPress 4.7", "Zaktualizuj WordPress do wspieranej wersji.", "signature")
        finding(c, sid, f"web:http://{ip}:8089", "medium", "Panel administracyjny bazy danych (Adminer)",
                "/ -> Login - Adminer", "Ogranicz dostęp do panelu (VPN / allowlista IP).", "signature")
        if i == passes - 1:
            finding(c, sid, f"web:http://{ip}:8090", "critical", "Celowo podatna aplikacja (DVWA) wystawiona",
                    "title: Damn Vulnerable Web Application", "Usuń DVWA ze środowiska dostępnego z sieci.", "signature")
    c.execute("INSERT OR REPLACE INTO range_notes VALUES(?,?,?,?)",
              (thash, "lab AGH · dane demonstracyjne", "demo", now))


def seed_big(c, now):
    base_hosts = []
    for blk in range(16):
        n = rnd.randint(18, 52)
        for o in rnd.sample(range(1, 255), n):
            base_hosts.append(f"10.0.{blk}.{o}")
    targets = ["10.0.0.0/20"]
    common = [(22, "ssh", "OpenSSH 8.9p1"), (80, "http", "nginx 1.24"), (443, "https", "nginx 1.24"),
              (3389, "rdp", ""), (445, "microsoft-ds", ""), (8080, "http", "Apache Tomcat 9.0")]
    host_ports = {h: rnd.sample(common, rnd.randint(1, 3)) for h in base_hosts}
    flappers = rnd.sample(base_hosts, 9)
    passes = 6
    for i in range(passes):
        t = now - (passes - 1 - i) * DAY - 3600 * 5
        sid, thash = add_scan(c, "10.0.0.0/20", targets, t, 5400 + rnd.randint(-600, 900),
                              opts={"time_window_mins": 120, "rate_limit": 300}, hosts_total=4094)
        alive = [h for h in base_hosts if not (h in flappers and (i + int(h.rsplit(".", 1)[1])) % 2)]
        if i == passes - 1:
            alive = alive[:-14] + [f"10.0.{rnd.randint(0, 15)}.{rnd.randint(1, 254)}" for _ in range(11)]
        for h in alive:
            asset(c, sid, "ip", h)
            for p, svc, ver in host_ports.get(h, [(22, "ssh", "OpenSSH 7.4")]):
                if i == passes - 1 and h == base_hosts[40] and p == 22:
                    ver = "OpenSSH 9.6p1"
                asset(c, sid, "port", f"{h}:{p}", {"port": p, "service": svc, "version": ver})
                if p == 3389:
                    finding(c, sid, f"port:{h}:{p}", "high", "RDP wystawiony", f"{h}:3389",
                            "Schowaj RDP za VPN lub bramą RD.")
        if i == passes - 1:
            j = "10.0.3.40"
            asset(c, sid, "ip", j)
            asset(c, sid, "port", f"{j}:8443", {"port": 8443, "service": "https", "version": "Jetty 10"})
            wid = asset(c, sid, "web", f"https://{j}:8443",
                        {"url": f"https://{j}:8443", "status": 200, "title": "Dashboard [Jenkins]",
                         "server": "Jetty(10.0.13)", "tech": ["Jenkins 2.346", "Java"]})
            finding(c, sid, wid, "critical", "Panel administracyjny Jenkins dostępny bez uwierzytelnienia",
                    "GET / -> 200 Dashboard [Jenkins]", "Włącz uwierzytelnianie i ogranicz dostęp do panelu.", "signature")
            s = "10.0.7.17"
            asset(c, sid, "ip", s)
            asset(c, sid, "port", f"{s}:22", {"port": 22, "service": "ssh", "version": "OpenSSH 7.4"})
            finding(c, sid, f"port:{s}:22", "medium", "Przestarzały OpenSSH 7.4", "banner SSH-2.0-OpenSSH_7.4",
                    "Zaktualizuj OpenSSH.", "signature")
    c.execute("INSERT OR REPLACE INTO range_notes VALUES(?,?,?,?)",
              (thash, "serwerownia B · syntetyczne", "demo", now))


def seed_domains(c, now):
    targets = ["dmz.agh.example", "staging.agh.example", "www.agh.example"]
    for i, status in enumerate(["done", "done", "paused_window"]):
        t = now - (2 - i) * DAY - 3600 * 9
        sid, thash = add_scan(c, "dmz.agh.example, staging.agh.example, www.agh.example", targets,
                              t, 1800 if status == "done" else 3660, status=status,
                              opts={"time_window_mins": 60})
        if status != "done":
            continue
        for k, host in enumerate(targets):
            ip = f"192.0.2.{10 + k}"
            asset(c, sid, "domain", host)
            asset(c, sid, "ip", ip)
            asset(c, sid, "port", f"{ip}:443", {"port": 443, "service": "https", "version": "nginx"})
            tech = ["WordPress 5.8", "PHP/7.4"] if "staging" in host else ["nginx"]
            wid = asset(c, sid, "web", f"https://{host}",
                        {"url": f"https://{host}", "status": 200, "title": host, "server": "nginx", "tech": tech})
            if "staging" in host:
                finding(c, sid, wid, "high", "Środowisko staging dostępne publicznie", f"https://{host}",
                        "Schowaj staging za VPN/uwierzytelnieniem.", "signature")


def main():
    if os.path.exists(DB_PATH) and "--force" not in sys.argv:
        sys.exit(f"{DB_PATH} już istnieje - użyj --force, żeby nadpisać (to baza demo, nie produkcyjna).")
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    db.init()
    now = time.time()
    with db.conn() as c:
        seed_domains(c, now)
        seed_big(c, now)
        seed_lab(c, now)
    print(f"Zapisano syntetyczne dane demo do {DB_PATH}")


if __name__ == "__main__":
    main()
