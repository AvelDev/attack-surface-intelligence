# Dokumentacja techniczna - Attack Surface Intelligence

PoC systemu do discovery scan dużej infrastruktury, zbudowany pod zadanie konkursowe
CBI AGH (HackNation 2026). Stack: Python/FastAPI + SQLite + vanilla JS (uzasadnienie
wyboru stacku zamiast sugerowanego Go/Rust/C++ - patrz §7).

## 1. Architektura

```
przeglądarka: panel React (frontend/ → frontend/dist, serwowany pod /)
             + stare UI (static/, vanilla JS, pod /legacy i /command-center)
        │ HTTP + ciasteczko sesji
        ▼
FastAPI (asi/main.py) ── auth.py (sesje, role) ── crypto.py (Fernet)
        │                                              │
        ├─ dashboard.py   (agregat panelu: zmiany, flapping, kolejka, mapa - GET /api/dashboard)
        ├─ _scheduler_loop() (wątek w tle, harmonogramy cykliczne)
        ▼                                              ▼
  scanner.py (orkiestracja pipeline'u)         SQLite (asi/db.py, WAL)
        │
        ├─ targets.py      (parsowanie/walidacja CIDR/host/domena, limit skali)
        ├─ signatures.py   (silnik własnych sygnatur, SSRF/ReDoS-safe)
        ├─ geo.py          (geolokalizacja IP dla Command Center, nie dla skanu)
        ├─ gvm_scan.py     (opcjonalnie: głęboki skan OpenVAS/GVM, wątek w tle)
        ├─ defectdojo.py   (opcjonalnie: eksport findingów, URL walidowany jak SSRF)
        └─ narzędzia zewnętrzne: subfinder, dnsx, naabu/nmap, httpx, nuclei
           (każde ma fallback w czystym Pythonie, gdy niezainstalowane)
```

Jeden proces, jedna baza SQLite. Skany idą w tle w wątkach (`threading`), liczba
równoległych skanów ograniczona semaforem `scanner.JOB_SEM` (`ASI_MAX_WORKERS`,
domyślnie 4) zamiast dawnej ścisłej kolejki po jednym - duży skan nie blokuje
całkowicie reszty systemu. Zweryfikowane na żywo: skan `/20` (4094 adresów,
własna sieć) zakończony ze 556+ ustaleniami, score 100/100.

## 2. Pipeline discovery (asi/scanner.py: pipeline())

1. **Wejście** (`asi/targets.py`): formularz (tekst, jeden cel na linię/przecinek),
   upload CSV/JSON (`POST /api/scans/import-targets`), albo import gotowych wyników
   (`POST /api/scans/import-results`, format symetryczny do eksportu). CIDR
   rozwijane przez `ipaddress`, z twardym limitem `ASI_MAX_TARGETS` (domyślnie
   20000) sprawdzanym PRZED materializacją listy hostów (ochrona przed DoS przez
   jeden ogromny prefiks - p. §6).
2. **Enumeracja subdomen** (tylko dla celów-domen): `subfinder` + crt.sh (pasywne,
   Certificate Transparency), fallback: samo DNS celu.
3. **Rozwiązywanie DNS**: `dnsx`, fallback: `socket.gethostbyname_ex` wielowątkowo.
   Adresy prywatne znalezione *przez DNS* są domyślnie odrzucane (`ASI_ALLOW_PRIVATE=1`
   żeby włączyć) - ale adresy podane *wprost* jako cel/CIDR nigdy nie są filtrowane,
   bo to świadomy wybór użytkownika (skan własnej sieci 10.0.0.0/8 musi działać).
4. **Skan portów** (`batched_port_scan`): `naabu`/`nmap`/fallback TCP-connect.
   Adresy dzielone na **adaptacyjne paczki** - rozmiar kolejnej paczki dostosowuje
   się do zmierzonej przepustowości poprzedniej, celując w ok. 30 s/paczkę. Stąd
   widoczny, aktualizowany na żywo postęp (`scans.hosts_done/hosts_total`) i czas
   trwania zamiast jednej, nieprzerywalnej operacji na tysiącach hostów. Limit
   pakietów/s konfigurowalny per-skan (`rate_limit`, 1-10000).
   Każdy znaleziony port przechodzi dodatkową weryfikację (`verify_ports`) -
   odrzuca "fałszywe" porty, gdzie TCP handshake się udaje, ale usługa nie
   odpowiada (typowe dla pośredników/firewalli zwracających RST na wszystko).
   Osobno: host, który w tym przebiegu nie pokazał żadnego portu (narzędzie nic
   nie zgłosiło — to nie to samo co porty odrzucone przez weryfikację), jest
   sondowany ponownie raz (`retry_silent_hosts`). Po krótkiej przerwie idzie
   tani test osiągalności na kilku typowych portach, pod tym samym `rate_limit`.
   Pełny skan portów powtarza się tylko dla adresów, które przy tej próbie
   jednak odpowiedziały, więc chwilowo nieosiągalny host nie jest od razu
   uznany za martwy, a martwa część sieci nie jest skanowana drugi raz w całości.
   Pasek `hosts_done` przy tej powtórce się nie cofa.
5. **Sondowanie HTTP/HTTPS**: `httpx` (ProjectDiscovery), fallback: `urllib`.
   Zbiera tytuł, kod odpowiedzi, nagłówki, serwer, (fallback też) treść strony.
   Wbudowane kontrole: HTTP bez przekierowania na HTTPS, brak HSTS, brakujące
   nagłówki bezpieczeństwa (CSP/X-Content-Type-Options/X-Frame-Options),
   ujawnienie wersji w nagłówku `Server`, wygasający/niepoprawny certyfikat TLS,
   potencjalny panel administracyjny po tytule strony. Wykrywanie technologii/CMS
   (`detect_tech`) działa też w fallbacku bez `httpx` - nagłówki Server/X-Powered-By,
   nazwy ciasteczek sesji, znaczniki w treści (wp-content, Joomla!, meta generator) -
   regex na treści strony ograniczone rozmiarem wejścia (ReDoS, p. §4).
6. **Własne sygnatury** (`signatures.py`) - patrz §4.
7. **Nuclei** (opcjonalnie, `ctx.opts.nuclei`) i **OpenVAS/GVM** (opcjonalnie,
   `ctx.opts.gvm`, działa w osobnym wątku w tle, nie blokuje reszty - p. `docs/openvas.md`).

Harmonogram (`main._scheduler_loop`, wątek w tle, co 30 s) uruchamia zapisane
cyklicznie skany (`schedules`: cel, interwał godzinowy, okno czasowe). Jeśli pojedynczy
skan przekroczy swoje okno czasowe (`Ctx.check_time_limit`), pipeline rzuca `TimeoutError`,
`run_scan` łapie to osobno od zwykłego błędu i ustawia status `paused_window` - pełne
wznowienie (ponowny przebieg) następuje przy najbliższym `next_run`.

## 3. Model danych (asi/db.py)

| Tabela | Rola |
|---|---|
| `scans` | jeden wiersz = jedno uruchomienie (wiele celów naraz); `target_hash` identyfikuje "tę samą" listę celów dla diffowania między przebiegami |
| `scan_targets` | płaska lista rozwiniętych celów danego skanu (audyt, wznowienia) |
| `assets` | zasoby: `domain`/`subdomain`/`ip`/`port`/`web`, z danymi (banery, nagłówki) |
| `edges` | krawędzie grafu powiązań (domena→subdomena→IP→port→usługa web) |
| `findings` | ustalenia: waga, tytuł, źródło (`builtin`/`nuclei`/`signature`/`openvas`/`import`), zalecenie |
| `users`/`sessions` | RBAC - patrz §5 |
| `signatures` | własne reguły detekcyjne - patrz §4 |
| `finding_overrides` | triage (zmiana wagi/zalecenia, oznaczenie false-positive) kluczowany po `(asset, title)`, nie po skanie - przetrwa kolejne przebiegi (pkt 14 specyfikacji) |
| `settings` | konfiguracja z UI zamiast tylko zmiennych środowiskowych (dziś: URL/klucz DefectDojo, klucz szyfrowany) |
| `schedules` | harmonogramy cykliczne: cel, interwał, okno czasowe |
| `triage` | decyzja z kolejki panelu (`open`/`ok`/`accepted`/`false_positive`) po `(asset, key)` - przetrwa kolejne przebiegi; `false_positive` zapisuje też override findingu |
| `range_notes` | notatka do zakresu (`target_hash`), np. właściciel, okno serwisowe |

Kolumna `scans.stop_requested` to ręczne zatrzymanie: `Ctx.check_time_limit()` sprawdza ją na
każdym etapie i kończy skan stanem `stopped` (wyniki częściowe zostają).

**Agregat panelu** (`asi/dashboard.py`, `GET /api/dashboard?range=&scan=`): dla każdego zakresu
porównuje ostatni przebieg z poprzednim (nowe / zniknięte / zmienione pola usług), na historii do
10 przebiegów liczy flapping i potwierdzone offline, składa porty pod host i web pod port (jedna
zmiana = jeden wiersz kolejki), podaje pewność jako k/N przebiegów, w których zasób był widoczny.
Mapa: hosty pogrupowane w /24; zakres do 16 hostów dostaje pasma portów. Akcje: `POST /api/triage`,
`PUT /api/ranges/{id}/note`, `POST /api/ranges/{id}/run`, `POST /api/scans/{id}/stop`,
`POST /api/defectdojo/export` - każda z kontrolą roli.

**Porównanie dwóch skanów** (`main._diff`): szuka ostatniego `done` skanu z tym
samym `target_hash`, porównuje zbiory ID zasobów i par (asset, tytuł) findingów -
stąd "nowe/zniknięte zasoby" i "nowe/naprawione ustalenia" bez przechowywania
osobnej historii zmian. Patrzy też wstecz na kilka poprzednich przebiegów, nie
tylko ostatni: `flapping_assets` to zasoby, które pojawiały/znikały niespójnie
między przebiegami (host "czasem odpowiada, czasem nie" - pytanie wprost z
wprowadzenia specyfikacji AGH), `confirmed_offline` to zasoby nieobecne w co
najmniej dwóch ostatnich przebiegach z rzędu (odróżnienie od zwykłego flappingu).

## 4. Moduł własnych sygnatur (asi/signatures.py)

Realizuje pkt 10 specyfikacji: bezpieczna detekcja obecności cechy, nigdy
eksploatacja. Typy: `header_present`, `cookie_name`, `html_regex`,
`footer_version_regex`, `path_check` (zwykły GET, bez prób logowania),
`favicon_hash` (SHA-256, nie Shodanowy MurmurHash3 - własny hash, bez dodatkowej
zależności). CRUD przez `/api/signatures`, stosowane raz na skan (nie per-asset)
do każdej zbadanej usługi web.

Dwa zabezpieczenia dodane po automatycznym security review:
- **SSRF**: `path_check` budował URL przez konkatenację stringów - wzorzec typu
  `//ewil.com` albo pełny `http://...` jako "ścieżka" potrafiłby przekierować
  żądanie na dowolny host. Teraz: `urljoin` + ponowna walidacja, że
  schemat/host/port po rozwinięciu wciąż zgadzają się z oryginalnym celem;
  przekierowania HTTP wyłączone.
- **ReDoS**: `html_regex`/`footer_version_regex` to regex od użytkownika
  (rola `add_remove_modify`) uruchamiany na treści strony - katastroficzny
  backtracking mógłby zawiesić skan. Dopasowanie idzie w osobnym procesie
  (`multiprocessing`, kontekst `fork`) z twardym limitem czasu i zabiciem
  procesu po przekroczeniu - wątek z `future.result(timeout=...)` **nie
  wystarcza**, bo zatrzymuje tylko czekanie, a porzucony wątek dalej pali CPU.
  Ten sam wzorzec ryzyka dotyczy też `scanner.detect_tech()` (CMS/tech
  fingerprinting, §2) - tam wzorzec jest nasz własny (nie od użytkownika), ale
  wejście (treść strony) i tak jest kontrolowane przez skanowany host, więc
  regex rozbity jest na ograniczone kroki ({0,N}) zamiast dwóch sąsiadujących
  nieograniczonych kwantyfikatorów na całym body.

## 5. RBAC i bezpieczeństwo danych (asi/auth.py, asi/crypto.py)

4 role w hierarchii `read < read_modify < add_remove_modify < admin`. Sesje po
ciasteczku (`HttpOnly`, `SameSite=Strict` - mitygacja CSRF, bo stanowe endpointy
nie mają własnego tokenu CSRF; `Secure` konfigurowalne przez `ASI_COOKIE_SECURE`
dla wdrożeń za TLS). Hasła: `pbkdf2_hmac` ze stdlib (bez nowej zależności).
Pierwszy użytkownik (`admin`, losowe hasło) tworzony automatycznie przy starcie.

Szyfrowanie w spoczynku (Fernet, `cryptography`): `findings.detail`,
`scans.log`, `assets.data` - kolumny z surowymi danymi ze skanowanych hostów
(banery, nagłówki, treść logów narzędzi). Identyfikatory/tytuły/wagi zostają
jawne, bo na nich operują diff i sortowanie bez potrzeby odszyfrowywania całej
tabeli. Klucz z `ASI_SECRET_KEY` albo auto-generowany i trwale zapisany
(`data/secret.key`, 0600) przy pierwszym starcie.

Import wyników (`/api/scans/import-results`) **nie ufa** `target_hash` z
przesłanego pliku - liczy własny w odrębnej przestrzeni nazw (prefiks `import:`),
żeby zaimportowany/spreparowany skan nie mógł podszyć się pod bazę porównawczą
(baseline) realnego celu i zatruć przyszłych diffów.

Ustawienie URL-a DefectDojo (`POST /api/settings/defectdojo`) jest celowo
`admin`-only (nie `add_remove_modify`) i waliduje host po rozwiązaniu DNS,
odrzucając loopback/prywatne/link-local adresy (`defectdojo.validate_url`) -
niżej uprzywilejowana rola mogłaby inaczej po cichu przekierować eksport
ustaleń ze WSZYSTKICH skanów na dowolny serwer (SSRF/eksfiltracja). Klucz API
przechowywany zaszyfrowany (`crypto.enc`); `get_config()` nigdy nie miesza
URL-a z env ze zmiennym z bazy (albo cała para z jednego źródła, albo z drugiego).

Frontend: dynamicznie budowane węzły DOM (triage, lista skanów w Command
Center, lista "confirmed_offline") przechodzą przez `esc()` - jedno realne
złapane ryzyko: wartości wstawiane w atrybut `onclick="...('${esc(x)}')"` są
bezpieczne jako HTML, ale **nie** jako JS-string-w-atrybucie (przeglądarka
dekoduje encje HTML przed uruchomieniem JS, więc zakodowany `'` wraca do
`'` i łamie string) - takie miejsca przerobione na `data-*` + `addEventListener`.
Skrypty z CDN (Three.js, OrbitControls, vis-network) mają `integrity`
(SRI, liczone samodzielnie z pobranych plików, nie z cudzych deklaracji).

## 6. Bezpieczeństwo skanowania

- Cel zawsze walidowany (`scanner.normalize_target`, `targets.expand`) -
  regex domeny, `ipaddress` dla IP/CIDR, opcjonalna allowlista
  (`ASI_ALLOWED_TARGETS`, obsługuje też zakresy CIDR).
- Komendy do narzędzi zewnętrznych uruchamiane jako lista argumentów
  (`subprocess.run(cmd, ...)`), nigdy przez powłokę - brak command injection.
- Limit liczby celów (`ASI_MAX_TARGETS`) sprawdzany przez własność `num_addresses`
  sieci (O(1), z długości prefiksu) **przed** rozwinięciem na listę hostów -
  inaczej pojedynczy wpis typu duży prefiks zaalokowałby ogromną listę w pamięci
  zanim limit w ogóle by zadziałał.
- Limit tempa skanowania (`rate_limit`) konfigurowalny per-skan, trafia do
  `naabu -rate`/`nmap --max-rate`.
- Migracja startowa (`db.init`) resetuje skany zawieszone w stanie
  `queued`/`running` po restarcie procesu.

## 7. Konteneryzacja (Docker)

Wszystkie narzędzia skanujące (nmap, subfinder, dnsx, naabu, httpx, nuclei)
wbudowane w jeden obraz - zero WSL/Kali/ręcznej instalacji `go install` dla
kogokolwiek, kto ma tylko Dockera. Dwuetapowy build: `golang:1.23-bookworm`
kompiluje narzędzia ProjectDiscovery (`GOTOOLCHAIN=auto`, bo ich wymagania
wobec wersji Go rosną szybciej niż warto gonić tagiem obrazu bazowego),
finalny obraz to `python:3.12-slim-bookworm` + `nmap` + skopiowane binarki.

Kontener chodzi jako root, ale z `cap_drop: [ALL]` + `cap_add: [NET_RAW, NET_ADMIN]`
w `docker-compose.yml` - realne least-privilege na poziomie Dockera (dokładnie te
dwie capability, nic więcej), bez kombinowania z `setcap` + non-root userem
wewnątrz kontenera. `scanner._naabu_can_syn()` wykrywa to przez `os.geteuid() == 0`
jako sygnał pierwszeństwa (na WSL/Kali bez roota sygnałem jest `getcap` na
pliku binarki - `scripts/install_tools.sh` ustawia to tam ręcznie) - w obu
przypadkach: jeśli żadnego nie da się potwierdzić, bezpieczny fallback do
wolniejszego, ale zawsze działającego connect scan.

`network_mode: host` jest wymagany na realne skanowanie sieci LAN/discovery -
domyślna sieć mostkowa Dockera (NAT) ogranicza widoczność i łamie SYN scan.
Działa natywnie na Linuksie; na Docker Desktop (Windows/Mac) trzeba przejść na
mapowanie portów (`ports:`) kosztem zasięgu skanowania ograniczonego do tego,
co widoczne z wewnętrznej maszyny wirtualnej Desktopa - udokumentowane w README.

Dane (`/data`: baza SQLite + klucz szyfrowania) i szablony nuclei trzymane w
nazwanych wolumenach - przetrwają restart/rebuild kontenera. Zweryfikowane
end-to-end: `docker compose up -d`, pełny skan `scanme.nmap.org` od zera do
"zakończony" wewnątrz kontenera, z potwierdzonym użyciem `naabu -s s` (SYN) -
skan portów zajął 4,3 s (dla porównania: dziesiątki sekund na connect scan
bez tej capability).

## 8. Dlaczego Python/FastAPI, nie Go/Rust/C++

Specyfikacja *sugeruje* (nie wymaga) języki niskozasobowe. Ciężką pracę i tak
wykonują binarki w C/Go (`nmap`, `naabu`, `nuclei`) wywoływane z Pythona -
Python tylko orkiestruje i batchuje, co jest dokładnie tym samym wzorcem,
na którym stoi reszta narzędzia. Przepisanie orkiestracji na Go w czasie
hackathonu byłoby czystym kosztem bez wpływu na kryteria oceny (funkcjonalność,
nie język implementacji).

## 9. Mapowanie na wymagania specyfikacji AGH

| Wymaganie | Gdzie w kodzie |
|---|---|
| Import listy IP/CIDR/domen, formularz + CSV/JSON | `asi/targets.py`, `POST /api/scans`, `POST /api/scans/import-targets` |
| Skan >10 000 adresów, podział na podgrupy, czas trwania | `scanner.batched_port_scan`, `scans.hosts_total/hosts_done/duration_s` |
| Ograniczanie tempa | `rate_limit` → `naabu -rate`/`nmap --max-rate` |
| Wykrywanie aktywnych hostów, podstawowych usług | `scan_ports` + `verify_ports` |
| HTTP/HTTPS: tytuł, kod, nagłówki, TLS, przekierowania | `probe_web`, `tls_check` |
| Proste wykrywanie technologii/CMS | `httpx -tech-detect` gdy zainstalowany, inaczej `scanner.detect_tech()` (fallback, pkt 2 w §2) |
| Panel administracyjny, środowisko testowe | `ADMIN_RE` na tytule strony |
| Porównanie dwóch skanów, nowe/zniknięte/zmienione | `main._diff` |
| Hosty niestabilne, ocena po kolejnych skanach | `_diff`: `flapping_assets`, `confirmed_offline` |
| Host niestabilny w ramach jednego skanu (ponowne sondowanie) | `retry_silent_hosts` |
| Własne sygnatury detekcyjne | `asi/signatures.py` |
| Formularz + import ręczny/CSV/JSON, te same reguły | `_start_scan` używane przez oba wejścia |
| RBAC, 4 konkretne role | `asi/auth.py` |
| Edycja wartości niezależnie od stanu skanu, przetrwa kolejne skany | `PATCH /api/findings/{id}` + `finding_overrides` |
| Dashboard/UI dla każdej roli | `static/index.html`, rola z `/api/me` steruje widocznością kontrolek |
| Szyfrowanie wrażliwych pól w spoczynku | `asi/crypto.py` |
| Integracja z DefectDojo | `asi/defectdojo.py` |
| Harmonogram - okno czasowe i częstotliwość | `main._scheduler_loop`, `schedules`, `Ctx.check_time_limit` (§2, §7) |
| Łatwość uruchomienia (kryterium 20%) | `Dockerfile` + `docker-compose.yml` (§7) - jedna komenda, bez WSL |

## 10. Znane zaległości (uczciwie, dla jury)

- **Wznowienie po oknie czasowym** (`paused_window`) uruchamia cały skan od
  nowa przy kolejnym `next_run`, nie kontynuuje od zapisanego postępu - prosty,
  ale świadomy kompromis czasowy na hackathon, nie prawdziwe checkpointowanie.
- Brak zautomatyzowanych testów (pytest) poza doraźnymi skryptami weryfikacyjnymi
  używanymi podczas developmentu.
- `network_mode: host` (Docker) działa w pełni tylko na natywnym Linuksie -
  na Docker Desktop (Windows/Mac) skanowanie LAN jest ograniczone (§7).
