# Dokumentacja techniczna - Attack Surface Intelligence

PoC systemu do discovery scan dużej infrastruktury, zbudowany pod zadanie konkursowe
CBI AGH (HackNation 2026). Stack: Python/FastAPI + SQLite + vanilla JS (uzasadnienie
wyboru stacku zamiast sugerowanego Go/Rust/C++ - patrz §7).

## 1. Architektura

```
przeglądarka (static/index.html, vanilla JS)
        │ HTTP + ciasteczko sesji
        ▼
FastAPI (asi/main.py) ── auth.py (sesje, role) ── crypto.py (Fernet)
        │                                              │
        ▼                                              ▼
  scanner.py (orkiestracja pipeline'u)         SQLite (asi/db.py, WAL)
        │
        ├─ targets.py      (parsowanie/walidacja CIDR/host/domena, limit skali)
        ├─ signatures.py   (silnik własnych sygnatur, SSRF/ReDoS-safe)
        ├─ gvm_scan.py     (opcjonalnie: głęboki skan OpenVAS/GVM, wątek w tle)
        ├─ defectdojo.py   (opcjonalnie: eksport findingów)
        └─ narzędzia zewnętrzne: subfinder, dnsx, naabu/nmap, httpx, nuclei
           (każde ma fallback w czystym Pythonie, gdy niezainstalowane)
```

Jeden proces, jedna baza SQLite. Skany idą w tle w wątkach (`threading`), liczba
równoległych skanów ograniczona semaforem `scanner.JOB_SEM` (`ASI_MAX_WORKERS`,
domyślnie 4) zamiast dawnej ścisłej kolejki po jednym - duży skan nie blokuje
całkowicie reszty systemu.

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
5. **Sondowanie HTTP/HTTPS**: `httpx` (ProjectDiscovery), fallback: `urllib`.
   Zbiera tytuł, kod odpowiedzi, nagłówki, serwer, (fallback też) treść strony.
   Wbudowane kontrole: HTTP bez przekierowania na HTTPS, brak HSTS, brakujące
   nagłówki bezpieczeństwa (CSP/X-Content-Type-Options/X-Frame-Options),
   ujawnienie wersji w nagłówku `Server`, wygasający/niepoprawny certyfikat TLS,
   potencjalny panel administracyjny po tytule strony.
6. **Własne sygnatury** (`signatures.py`) - patrz §4.
7. **Nuclei** (opcjonalnie, `ctx.opts.nuclei`) i **OpenVAS/GVM** (opcjonalnie,
   `ctx.opts.gvm`, działa w osobnym wątku w tle, nie blokuje reszty - p. `docs/openvas.md`).

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

**Porównanie dwóch skanów** (`main._diff`): szuka ostatniego `done` skanu z tym
samym `target_hash`, porównuje zbiory ID zasobów i par (asset, tytuł) findingów -
stąd "nowe/zniknięte zasoby" i "nowe/naprawione ustalenia" bez przechowywania
osobnej historii zmian.

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

## 7. Dlaczego Python/FastAPI, nie Go/Rust/C++

Specyfikacja *sugeruje* (nie wymaga) języki niskozasobowe. Ciężką pracę i tak
wykonują binarki w C/Go (`nmap`, `naabu`, `nuclei`) wywoływane z Pythona -
Python tylko orkiestruje i batchuje, co jest dokładnie tym samym wzorcem,
na którym stoi reszta narzędzia. Przepisanie orkiestracji na Go w czasie
hackathonu byłoby czystym kosztem bez wpływu na kryteria oceny (funkcjonalność,
nie język implementacji).

## 8. Mapowanie na wymagania specyfikacji AGH

| Wymaganie | Gdzie w kodzie |
|---|---|
| Import listy IP/CIDR/domen, formularz + CSV/JSON | `asi/targets.py`, `POST /api/scans`, `POST /api/scans/import-targets` |
| Skan >10 000 adresów, podział na podgrupy, czas trwania | `scanner.batched_port_scan`, `scans.hosts_total/hosts_done/duration_s` |
| Ograniczanie tempa | `rate_limit` → `naabu -rate`/`nmap --max-rate` |
| Wykrywanie aktywnych hostów, podstawowych usług | `scan_ports` + `verify_ports` |
| HTTP/HTTPS: tytuł, kod, nagłówki, TLS, przekierowania | `probe_web`, `tls_check` |
| Proste wykrywanie technologii/CMS | `httpx -tech-detect` (gdy zainstalowany - **brak w fallbacku pythonowym, zob. zaległości**) |
| Panel administracyjny, środowisko testowe | `ADMIN_RE` na tytule strony |
| Porównanie dwóch skanów, nowe/zniknięte/zmienione | `main._diff` |
| Własne sygnatury detekcyjne | `asi/signatures.py` |
| Formularz + import ręczny/CSV/JSON, te same reguły | `_start_scan` używane przez oba wejścia |
| RBAC, 4 konkretne role | `asi/auth.py` |
| Edycja wartości niezależnie od stanu skanu | `PATCH /api/findings/{id}` |
| Dashboard/UI dla każdej roli | `static/index.html`, rola z `/api/me` steruje widocznością kontrolek |
| Szyfrowanie wrażliwych pól w spoczynku | `asi/crypto.py` |
| Integracja z DefectDojo | `asi/defectdojo.py` |
| Harmonogram - okno czasowe i częstotliwość | **brak - zaległość, zob. README/TODO** |

## 9. Znane zaległości (uczciwie, dla jury)

- **Harmonogram skanu** (okno czasowe + częstotliwość uruchamiania) - wymóg z
  minimalnego zakresu specyfikacji, nieukończony. Skany uruchamia się ręcznie
  albo przez API; nie ma cyklicznego triggera ani wymuszania okna czasowego.
- **Wykrywanie technologii/CMS w fallbacku bez `httpx`** - działa tylko gdy
  `httpx` (ProjectDiscovery) jest zainstalowany; czysto-pythonowa ścieżka
  zwraca pustą listę technologii.
- **Retry dla niestabilnych hostów** - skan jest jednorazowy, bez automatycznego
  powtórzenia pomiaru dla hosta, który akurat nie odpowiedział.
- Brak zautomatyzowanych testów (pytest) poza doraźnymi skryptami weryfikacyjnymi
  używanymi podczas developmentu.
