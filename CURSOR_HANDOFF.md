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

## 2. Co jest zrobione (branch `babunia`, ostatni commit widoczny w `git log`)

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
  `scanner.detect_tech()` (nagłówki/cookies/body, regex bounded przeciw ReDoS).
- **Diff i niestabilność**: `main._diff` - nowe/zniknięte/zmienione, plus `flapping_assets`
  (host pojawia się/znika niespójnie) i `confirmed_offline` (nieobecny ≥2 ostatnie skany).
  W ramach jednego przebiegu host bez żadnej odpowiedzi jest sondowany ponownie raz
  (`scanner.retry_silent_hosts`): tani test osiągalności, pełny skan portów tylko
  dla tych, które jednak odpowiedziały, ten sam `rate_limit`. Hosty z portami
  odrzuconymi przez `verify_ports` nie wchodzą w tę ścieżkę.
- **Harmonogram**: `main._scheduler_loop` (wątek co 30s), tabela `schedules`, okno czasowe
  (`Ctx.check_time_limit` → `paused_window` jeśli przekroczone).
- **DefectDojo**: `asi/defectdojo.py`, eksport jako "Generic Findings Import", URL walidowany
  (DNS + `is_global`, odrzuca loopback/prywatne/link-local - ochrona SSRF), ustawienie
  **admin-only** (nie `add_remove_modify` - to był błąd, naprawiony).
- **Command Center**: `/command-center`, osobny wizualny dashboard (globus Three.js,
  trend ryzyka ze sparkline), wpięty w te same dane co główny widok.
- **Triage**: `PATCH /api/findings/{id}` + tabela `finding_overrides` (keyed po
  `asset,title`, nie po skanie - przetrwa kolejne przebiegi).
- **Docker**: `Dockerfile` (multi-stage, wszystkie narzędzia wbudowane) + `docker-compose.yml`
  (`cap_drop: [ALL]` + `cap_add: [NET_RAW]`, `network_mode: host` dla Linuksa).
  **Zweryfikowane end-to-end** (patrz §4) - login, pełny skan, SYN scan (naabu -s s) działa
  z samym NET_RAW, restart całej distro WSL nie psuje danych (wolumeny).

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

1. **Prawdziwe wznowienie po `paused_window`** - dziś cały skan startuje od nowa przy
   kolejnym `next_run`, nie kontynuuje od zapisanego postępu.
2. **Brak zautomatyzowanych testów** (pytest) - tylko doraźne skrypty weryfikacyjne używane
   podczas developmentu, nie wchodzą do repo.
3. Prezentacja (≤10 slajdów + demo) - **explicite odłożona przez użytkownika na koniec**,
   dopiero gdy produkt gotowy. Szkic/draft: `docs/prezentacja.html`, scenariusz demo:
   `docs/screnariusz.md` (bloki A-N, gotowe złożenia czasowe 2/3/5/6+ min).
4. Nie zrobione i NIE w zakresie spec: integracja Shodan/CISA KEV/NVD - nie dodawaj tego.

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

**Docker Desktop (Windows/Mac)**: w `docker-compose.yml` zakomentuj `network_mode: host`,
odkomentuj `ports: ["8000:8000"]` - bez tego kontener może nie być widoczny na porcie.
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
- Jeśli na hoście działa Tailscale: potrafi zbijać MTU interfejsu WSL do 1280, co psuje
  właśnie ten `portproxy`-owy tunel (TCP handshake przechodzi, transfer danych wisi).
  Fix: `wsl -d <nazwa> -u root -- ip link set eth0 mtu 1500` PO wyłączeniu/`tailscale down`
  (ustawianie 1500 z włączonym Tailscale psuje też bezpośredni dostęp - nie robić na ślepo).
  Nie jest to trwałe - wraca do 1280 po kolejnym połączeniu Tailscale.
- WSL2 usypia distro bez aktywnego procesu w środku (nawet serwer w tle to nie wystarczy,
  jeśli coś go ubije) - jeśli appka nagle nie odpowiada, sprawdź najpierw `wsl -l -v`, nie
  zakładaj że dane/kontener są uszkodzone.

## 7. Struktura repo

```
asi/            - backend (FastAPI), jeden moduł na funkcję (scanner/targets/auth/crypto/
                   signatures/defectdojo/geo/gvm_scan/db/main)
static/          - index.html (główny dashboard), command_center.html (wizualny widok)
docs/            - architektura.md (techniczne), screnariusz.md (demo), openvas.md (GVM),
                   prezentacja.html (draft slajdów, NIE priorytet)
scripts/         - install_tools.sh (setup bez Dockera)
deploy/          - asi.service (systemd, dla wdrożenia bez Dockera)
Dockerfile, docker-compose.yml, .dockerignore
run.sh           - start bez Dockera
requirements.txt
```

## 8. Repo

`https://github.com/AvelDev/attack-surface-intelligence`, branch **`babunia`** (nie `main` -
sprawdź czy trzeba będzie to kiedyś zmergować, ale na razie cała praca jest tutaj).
Commituj małymi, opisowymi commitami jak dotychczasowa historia w `git log` - widać tam
wzorzec (co i czemu, nie tylko co).
