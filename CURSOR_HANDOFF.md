# Handoff dla Cursora - Attack Surface Intelligence (AGH HackNation 2026)

Ten plik jest wejściem dla innego asystenta (Cursor), który przejmuje dalszą pracę nad tym
projektem. Przeczytaj go cały przed jakąkolwiek zmianą kodu.

## 0. Zasada naczelna - trzymaj się specyfikacji, nie zgaduj

Pełna treść zadania konkursowego leży w `../rules/` (katalog siostrzany, jeden poziom wyżej
niż ten repo):
- `AGH - Pełna treść zadania konkursowego.pdf` - **to jest jedyne źródło prawdy** co ma
  powstać. Nie dodawaj funkcji, których tam nie ma (np. integracji z Shodan/CISA KEV/NVD -
  to był pomysł z wcześniejszej, nieaktualnej wersji pitcha, nie z realnej specyfikacji).
- `AGH - Regulamin zadania konkursowego.pdf` - zasady formalne (co trzeba oddać, deadline,
  format prezentacji).

Jury ocenia wg wag (parafraza z `docs/architektura.md` §9 - tam dokładne mapowanie wymóg→kod):
- 30% - skuteczność discovery w dużej infrastrukturze (>10 000 IP)
- 20% - jakość techniczna, dokumentacja, integracja z DefectDojo, **łatwość uruchomienia**
- 15% - bezpieczeństwo działania, kontrola intensywności skanu
- 15% - wykrywanie zmian w czasie, obsługa niestabilnych hostów
- 10% - fingerprinting/CMS/nagłówki, własne sygnatury
- 10% - RBAC + szyfrowanie danych "at rest"

Przed dodaniem czegoś, czego nie ma wprost w spec albo w sekcji "Pending" niżej - zapytaj,
nie zgaduj. Ten projekt ma limitowany czas/kredyty, więc priorytet to **domknięcie realnych
zaległości**, nie refaktor czy nowe funkcje poza zakresem.

## 1. Stack i dlaczego

Python/FastAPI + SQLite (WAL) + vanilla JS. Świadomy wybór mimo że spec *sugeruje* (nie
wymaga) język niskozasobowy - ciężką pracę i tak robią binarki w Go/C (nmap, naabu, nuclei),
Python tylko orkiestruje. Pełne uzasadnienie: `docs/architektura.md` §8.

Zewnętrzne narzędzia (każde ma fallback w czystym Pythonie, gdy niezainstalowane):
`subfinder`, `dnsx`, `naabu`/`nmap`, `httpx`, `nuclei`. Wszystkie wbudowane w obraz Docker.

## 2. Co jest zrobione (branch `main`, ostatni commit widoczny w `git log`)

Pełny, zweryfikowany opis w `docs/architektura.md` (10 sekcji, mapowanie wymóg→kod w §9).
Skrót:

- **Skala**: import CIDR/IP/domen (formularz, CSV, JSON), hard limit `ASI_MAX_TARGETS`
  sprawdzany PRZED materializacją listy hostów, adaptacyjne batche portów, `rate_limit`
  per-skan, `hosts_total/hosts_done/duration_s` na żywo. Zweryfikowane realnym skanem
  własnej sieci `/20` (4094 hostów, 556 ustaleń, score 100, ~97 min).
- **RBAC**: 4 role (`read < read_modify < add_remove_modify < admin`), sesje cookie
  (`HttpOnly`, `SameSite=Strict`), `asi/auth.py`.
- **Szyfrowanie at-rest**: Fernet (`asi/crypto.py`) na `findings.detail`/`scans.log`/
  `assets.data`. Identyfikatory/tytuły/wagi jawne (diff/sortowanie).
- **Własne sygnatury**: `asi/signatures.py` - header/cookie/regex/path-check/favicon-hash,
  z ochroną SSRF (`urljoin`+re-walidacja hosta) i ReDoS (`multiprocessing` z timeoutem,
  nie `ThreadPoolExecutor` - to nie wystarcza, zatrzymuje tylko czekanie).
- **Fingerprinting/CMS**: `httpx -tech-detect` gdy zainstalowany, inaczej fallback
  `scan.web.detect_tech()` (nagłówki/cookies/body, regex bounded przeciw ReDoS).
- **Diff i niestabilność**: `main._diff` - nowe/zniknięte/zmienione, plus `flapping_assets`
  (host pojawia się/znika niespójnie) i `confirmed_offline` (nieobecny ≥2 ostatnie skany).
  W ramach jednego przebiegu host bez żadnej odpowiedzi jest sondowany ponownie raz
  (`scan.ports.retry_silent_hosts`): tani test osiągalności, pełny skan portów tylko
  dla tych, które jednak odpowiedziały, ten sam `rate_limit`. Hosty z portami
  odrzuconymi przez `verify_ports` nie wchodzą w tę ścieżkę.
- **Harmonogram + prawdziwe wznowienie**: `main._scheduler_loop` (wątek co 30s), tabela
  `schedules`, okno czasowe (`Ctx.check_time_limit` → `paused_window` jeśli przekroczone).
  `scans.checkpoint` (ip_of/root_id/pending_ips/hosts_total) zapisywany przyrostowo per paczka
  portów - wznowienie (`_run_schedule_entry` albo ręcznie `POST /api/scans/{id}/resume`)
  kontynuuje TEN SAM `scan_id` od checkpointu, nie zaczyna od zera. `time_window_mins` to
  budżet NA SESJĘ (liczony od uruchomienia, nie od `created`). Zweryfikowane end-to-end przez
  realne API: dwa kolejne okna czasowe, `hosts_done` rośnie ciągle 0→200→400.
- **DefectDojo**: `asi/defectdojo.py`, eksport jako "Generic Findings Import", URL walidowany
  (DNS + `is_global`, odrzuca loopback/prywatne/link-local - ochrona SSRF), ustawienie
  **admin-only** (nie `add_remove_modify` - to był błąd, naprawiony).
- **Command Center**: `/command-center`, osobny wizualny dashboard (globus Three.js,
  trend ryzyka ze sparkline), wpięty w te same dane co główny widok.
- **Triage**: `PATCH /api/findings/{id}` + tabela `finding_overrides` (keyed po
  `asset,title`, nie po skanie - przetrwa kolejne przebiegi).
- **Docker**: `Dockerfile` (3-stage: `golang` do narzędzi PD, `node` do builda panelu React,
  finalny `python:3.12-slim`; `/opt/pd/bin` jako osobny PATH-wpis PRZED `/usr/local/bin` - inaczej
  `pip install httpx` podkłada własny skrypt `httpx` i po cichu zasłania binarkę ProjectDiscovery)
  + `docker-compose.yml` (`cap_drop: [ALL]` + `cap_add: [NET_RAW]`, `network_mode: host` dla
  Linuksa) + `docker-compose.desktop.yml` (nakładka na Docker Desktop/Windows/Mac - zamienia
  `network_mode: host` na publikowanie portu, `ASI_PUBLISH` ustala adres:port, domyślnie
  `127.0.0.1:8000`). HEALTHCHECK w obrazie (czysty Python, bez curl). `scripts/docker_smoke_test.sh`
  - budowa + efemeryczny kontener testowy (auto-usuwany po teście), opcjonalnie pełny skan.
  **Zweryfikowane end-to-end** (patrz §4) - login, pełny skan, SYN scan (naabu -s s) działa
  z samym NET_RAW, restart całej distro WSL nie psuje danych (wolumeny).
- **Nagłówki bezpieczeństwa na własnym API** (`asi/main.py::_security_headers`) - CSP,
  X-Frame-Options, X-Content-Type-Options, Referrer-Policy (+ HSTS gdy `ASI_COOKIE_SECURE=1`).
  To samo, czego `SEC_HEADERS` w `scan/web.py` oczekuje od zbadanych hostów.
- **CI** (`.github/workflows/`): `docker-smoke.yml` (build + smoke test bez skanu) i
  `tests.yml` (pytest) na każdy push/PR do `main`.
- **Panel React** (`frontend/`, Vite): nowy UI pod `/` - 4 widoki (zmiany od przebiegu, mapa
  przestrzeni adresowej, kolejka triage z eksportem do DefectDojo, tabela zakresów z oknem
  czasowym jako budżetem). Stary vanilla-JS UI (skan/sygnatury/harmonogram/użytkownicy) dalej
  żyje pod `/legacy`. Backend dla panelu: `asi/dashboard.py`. Obraz Dockera buduje panel sam
  (etap `node`); serwer bez `frontend/dist` cicho wraca do starego UI.

### Bezpieczeństwo - co było łatane (nie próbuj tego "naprawiać" ponownie bez powodu)

Lista realnych podatności znalezionych i zamkniętych w tym repo (historia w `git log`,
szczegóły w `docs/architektura.md` §4-5): SSRF w `path_check` sygnatur, ReDoS w user-regex
i w CMS-detection regexach, zatrucie baseline diffa przez import (`target_hash` liczony
server-side, nie z pliku), info-disclosure URL-a DefectDojo w `/api/tools`, SSRF/eksfiltracja
przez `/api/settings/defectdojo` (było `add_remove_modify`, powinno być `admin` - naprawione),
stored XSS przez inline `onclick` w przycisku triage (trzeba `data-*`+`addEventListener`,
bo `esc()` HTML nie chroni wewnątrz atrybutu JS-handlera), brak SRI na CDN-owych skryptach
(dodane, liczone samodzielnie z pobranych plików, nie z cudzych deklaracji), nadmiarowy
`NET_ADMIN` w Dockerze (usunięty, SYN scan potrzebuje tylko `NET_RAW`).

## 3. Znane zaległości (priorytet w tej kolejności)

Z `docs/architektura.md` §10, nie zmyślone:

1. **Testy automatyczne są ograniczone** (`tests/`, `pytest`, uruchamiane w CI -
   `.github/workflows/tests.yml`) - pokrywają tylko regresję na rzeczach już raz
   naprawionych (RBAC, SSRF w sygnaturach/DefectDojo, namespace `import:`,
   `retry_silent_hosts`). Brak testów na sam pipeline skanowania (wymagałby mocków
   narzędzi zewnętrznych albo realnego środowiska testowego) - jeśli dodajesz nową
   logikę bezpieczeństwa, dodaj do niej test w `tests/`, nie tylko kod.
2. Prezentacja - **zrobiona, DWIE wersje**: `docs/prezentacja.pptx` (10 slajdów, zgodna z
   limitem specyfikacji §4 - TA idzie do jury) i `docs/prezentacja_pelna.pptx` (20 slajdów,
   pełny materiał techniczny/referencyjny, NIE do pokazania jury - za dużo slajdów). Spec
   wymaga demo URUCHOMIONEGO NA ŻYWO podczas prezentacji (lokalnie/w środowisku testowym),
   nie nagrania wideo - jeśli ktoś każe Ci zrobić "filmik", upewnij się, że to dodatek/backup,
   nie zamiennik live demo. Szkic/draft HTML: `docs/prezentacja.html` (starsza wersja,
   nieaktualna). Scenariusz demo: `docs/screnariusz.md` (bloki A-N).
3. Nie zrobione i NIE w zakresie spec: integracja Shodan/CISA KEV/NVD - nie dodawaj tego.

## 4. Co było faktycznie zweryfikowane (nie tylko napisane)

- Pełny smoke test w kontenerze Docker na czysto zrestartowanej distro WSL: build od zera,
  `docker compose logs` pokazuje hasło admina, HTTP 200, `docker compose exec asi id` = root,
  login przez API, `POST /api/scans` na `scanme.nmap.org`, skan dochodzi do `done` z realnymi
  ustaleniami, log potwierdza `naabu ... -s s` (SYN, nie connect scan).
- To samo powtórzone po **pełnym restarcie całej distro WSL** (nie tylko kontenera) -
  dane w named-volumes przetrwały, trzeba tylko odpalić distro ponownie (`wsl -d <nazwa>`),
  bo WSL2 usypia distro bez aktywnego procesu.
- Test w trybie `ports: ["8000:8000"]` (symulacja Docker Desktop, bridge networking
  zamiast `network_mode: host`) - działa identycznie.
- Test z usuniętym `NET_ADMIN` (sam `NET_RAW`) - SYN scan wciąż działa, zweryfikowane.
- Realny skan własnej sieci `/20` (4094 hosty) dokończony z sukcesem na żywym serwerze
  (branch demo, osobna maszyna) - 556 ustaleń, score 100, ~97 min.

## 5. Jak to odpalić

```
docker compose up -d --build
docker compose logs asi    # hasło admina - wypisane RAZ, przy pierwszym starcie na pustym wolumenie
```
→ `http://localhost:8000`, login `admin` + hasło z logu.

**Docker Desktop (Windows/Mac)**: nie edytuj `docker-compose.yml` ręcznie - użyj nakładki:
```
docker compose -f docker-compose.yml -f docker-compose.desktop.yml up -d --build
```
Domyślnie publikuje na `127.0.0.1:8000` (tylko localhost); żeby było widoczne z LAN/innego
hosta: `ASI_PUBLISH=0.0.0.0:8000 docker compose -f docker-compose.yml -f docker-compose.desktop.yml up -d --build`.
Skanowanie LAN będzie ograniczone do tego, co widzi wirtualna maszyna Docker Desktop
(to jest akceptowalne ograniczenie, nie bug - opisane w README i architektura.md §7).

Bez Dockera: `bash scripts/install_tools.sh && bash run.sh` (wymaga Ubuntu/WSL).

Nie ma żadnego stałego/hardkodowanego hasła - to świadome (bezpieczeństwo, brak sekretu
w repo). Jeśli hasło z logu "przepadnie": `docker compose down -v && docker compose up -d`
(usuwa wolumen, generuje nowe konto admin od zera - to kasuje WSZYSTKIE dane, nie robić tego
bez potrzeby na instancji, na której są realne wyniki skanów).

## 6. Pułapki środowiskowe (jeśli pracujesz na tym samym Windows+WSL hoście)

- Dwie distro WSL używane równolegle: jedna do Dockera (budowanie/testy), druga do żywego
  demo poza Dockerem - traktuj je jako całkowicie niezależne, nie zakładaj współdzielonego
  stanu.
- `network_mode: host` w Dockerze wymaga natywnego Linuksa - w WSL2 działa, ale `localhost`
  z Windowsa nie zawsze przekazuje się automatycznie do NIEdomyślnej distro WSL (działa od
  razu tylko dla distro oznaczonej jako default w `wsl -l -v`). Obejście: dostęp przez IP
  distro (`wsl -d <nazwa> -- hostname -I`) albo `netsh interface portproxy add v4tov4
  listenport=8000 listenaddress=0.0.0.0 connectport=8000 connectaddress=<IP distro>`
  (wymaga PowerShell jako Administrator) + `New-NetFirewallRule` dla dostępu z LAN.
- Jeśli na hoście działa jakikolwiek VPN (Tailscale, ProtonVPN/"ProTUN" i podobne - każdy
  dodaje własny wirtualny adapter): potrafi zbijać MTU interfejsu WSL do 1280 i/lub tworzyć
  "black hole" (TCP handshake przechodzi, odpowiedź HTTP nigdy nie wraca) na `portproxy`-owym
  tunelu Windows→WSL. `tailscale down` samo NIE wystarcza - usługa i wirtualny adapter
  zostają aktywne (`Get-Service Tailscale` dalej `Running`, `Get-NetAdapter` dalej `Up`) i
  nadal wpływają na MTU. Jedyny pewny fix: **całkowicie zamknąć/wyjść z każdej aplikacji VPN**
  (nie tylko "disconnect" - "Quit" z zasobnika), potem ewentualnie doładować
  `wsl -d <nazwa> -u root -- ip link set eth0 mtu 1500`. Nie jest to trwałe - MTU może wrócić
  do 1280 przy ponownym połączeniu VPN. Diagnoza: `curl.exe -v http://localhost:8000/` -
  "Established connection" + zero bajtów odpowiedzi = to jest to (nie błąd appki).
- WSL2 usypia distro bez aktywnego procesu w środku (nawet serwer w tle to nie wystarczy,
  jeśli coś go ubije) - jeśli appka nagle nie odpowiada, sprawdź najpierw `wsl -l -v`, nie
  zakładaj że dane/kontener są uszkodzone.

## 7. Struktura repo

```
asi/            - backend (FastAPI), warstwy: config/db/repo/ → logika → api/ (routery) + scan/ (silnik)
frontend/        - panel React (Vite) - nowy UI pod "/"; stary UI dalej pod "/legacy"
static/          - index.html (stary dashboard), command_center.html (wizualny widok)
docs/            - architektura.md (techniczne), screnariusz.md (demo), openvas.md (GVM),
                   prezentacja.html (draft slajdów, NIE priorytet)
lab/             - podatny lab (docker-compose + Traefik) do demo, quickstart.sh
scripts/         - install_tools.sh (setup bez Dockera), docker_smoke_test.sh (smoke test obrazu),
                   seed_demo.py (dane demo, syntetyczne, nie odpalają skanu)
tests/           - pytest, regresja RBAC/SSRF/namespace-importu/retry_silent_hosts (§3.2)
.github/workflows/ - docker-smoke.yml, tests.yml (CI na push/PR do main)
deploy/          - asi.service (systemd, dla wdrożenia bez Dockera)
Dockerfile, docker-compose.yml, docker-compose.desktop.yml, .dockerignore
DESIGN.md, PRODUCT.md - design system / produkt (panel React)
run.sh           - start bez Dockera
requirements.txt, requirements-dev.txt (pytest + httpx, tylko do testów)
```

## 8. Repo

`https://github.com/AvelDev/attack-surface-intelligence`, branch **`main`** (jedyny branch -
`babunia` zostało w to zlane i usunięte; stara historia `main` sprzed scalenia jest pod
tagiem `archive/main-before-babunia-merge`, dla porządku, nie do użycia).
Commituj małymi, opisowymi commitami jak dotychczasowa historia w `git log` - widać tam
wzorzec (co i czemu, nie tylko co).
