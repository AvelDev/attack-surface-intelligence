# Attack Surface Intelligence

[![CI](https://github.com/AvelDev/attack-surface-intelligence/actions/workflows/ci.yml/badge.svg)](https://github.com/AvelDev/attack-surface-intelligence/actions/workflows/ci.yml)

Web UI (FastAPI + React) orkiestrujące narzędzia z Kali/Ubuntu: subfinder → dnsx → naabu/nmap → httpx → (opcjonalnie) nuclei.
Brakujące narzędzie zastępuje fallback w czystym Pythonie. Wynik: graf zasobów, ustalenia z zaleceniami, wynik ryzyka 0-100,
diff względem poprzedniego skanu tego samego celu oraz raport HTML.

## Uruchomienie (Ubuntu / WSL)
    bash scripts/install_tools.sh   # nmap + narzędzia ProjectDiscovery (go install)
    bash run.sh                     # http://127.0.0.1:8000

Zmienne (wszystkie czyta `asi/config.py`): `ASI_HOST`, `ASI_PORT`, `ASI_DB`,
`ASI_ALLOWED_TARGETS=example.com,lab.local` (allowlista), `ASI_ALLOW_PRIVATE=1` (skanuj też adresy prywatne/loopback
znalezione w DNS), `ASI_SCHEDULER=0` (wyłącza automatyczne skany), `ASI_WEBHOOK_URL`.

## Automatyzacja i monitoring
- **Cykliczne skany**: w formularzu zaznacz „Sprawdzaj automatycznie” (codziennie / co tydzień / co miesiąc). Harmonogram działa
  w wątku w tle (`asi/scheduler.py`), tabela `schedules`, API `/api/schedules` (GET/POST/PATCH/DELETE).
- **Powiadomienia**: po każdym skanie porównanie z poprzednim (`asi/alerts.py`): nowe pilne problemy, pogorszenie oceny o >=10 pkt,
  nowe zasoby. API `/api/alerts`. Opcjonalny webhook: `ASI_WEBHOOK_URL` (JSON `{"text": "..."}`, Slack/Mattermost/Teams).
- **Dodatkowe kontrole** (`asi/checks.py`, tylko odczyt): ukryte pliki (.git, .env, kopie baz), SPF/DMARC (DNS-over-HTTPS),
  TLS 1.0/1.1, security.txt.
- **Trend oceny** w czasie w widoku wyniku (`trend` w `/api/scans/{id}`).

## Narzędzia, źródła danych i ustawienia
Każde narzędzie jest opcjonalne (fallback w Pythonie); stan widać w aplikacji: **Ustawienia** (prawy górny róg).

| Obszar | Narzędzia | Fallback |
|---|---|---|
| Subdomeny | subfinder, amass, assetfinder | crt.sh, HackerTarget, Anubis |
| DNS | dnsx, dnsrecon (AXFR) | resolver systemowy, własny AXFR |
| Porty | naabu, nmap | skan TCP w Pythonie |
| WWW | httpx, whatweb, wafw00f | zapytania HTTP, nagłówki, meta generator |
| TLS | sslyze, testssl.sh | kontrola TLS 1.0/1.1 |
| Adresy URL | gau, waybackurls, katana (tylko tryb dokładny) | Wayback CDX |
| Luki | nuclei (opcjonalnie) | pomijane |

**Wywiad zewnętrzny** (`asi/intel.py`): Shodan InternetDB (bez klucza) lub Shodan API, Censys Platform (token), CISA KEV
(lista podatności wykorzystywanych w atakach, cache 24 h), NVD (CVE dla wykrytych wersji), Have I Been Pwned (wycieki domeny;
wymaga domeny zweryfikowanej na koncie HIBP).

**Klucze API**: zapis w Ustawieniach, na serwerze (tabela `settings`, plik bazy z uprawnieniami 600). Po zapisaniu klucz nie wraca
przez API, interfejs pokazuje tylko gwiazdki. Zmienna `ASI_<NAZWA>` (np. `ASI_NVD_API_KEY`) ma pierwszeństwo.
Klucze leżą w bazie jako zwykły tekst, więc nie wystawiaj aplikacji bez uwierzytelnienia.

**Tryby**: domyślnie lekki (pasywny, bez crawlingu). „Tryb dokładny” (Ustawienia dodatkowe przy skanie) włącza crawling katana,
aktywną enumerację amass, whatweb `-a 3` i audyt TLS dla większej liczby hostów. Dłuższy skan i więcej ruchu na sprawdzanej stronie.

**Instalacja**: `bash scripts/install_tools.sh` (Ubuntu/WSL/Kali) lub `docker compose up --build` (obraz ze wszystkimi narzędziami,
dane w wolumenie `asi-data`).

## Bezpieczeństwo
- Skanuj wyłącznie zasoby, do których masz zgodę (UI wymaga potwierdzenia). Bezpieczny cel testowy: `scanme.nmap.org`.
- API uruchamia skany - nie wystawiaj go publicznie bez uwierzytelnienia (reverse proxy + auth). Zob. `deploy/asi.service`.
- Cel jest walidowany, komendy działają bez powłoki (brak command injection).

## Architektura
Warstwy zależą tylko w dół; SQL jest wyłącznie w `asi/repo/`, HTTP wyłącznie w `asi/api/`.

    asi/api/        routery FastAPI, kontrakty Pydantic, wyjątki domenowe -> 400/404/409, /api/health
    asi/            logika: scheduler (harmonogramy), alerts (reguła evaluate), history (diff), settings,
                    report (HTML/CSV), domain (ważności, ocena, werdykt), targets (walidacja celu)
    asi/scan/       silnik: pipeline (jawna lista etapów) -> dns, ports, web, urls, checks, intel; runner (kolejka)
    asi/repo/       repozytoria SQLite; asi/db.py - połączenie i wersjonowane migracje (PRAGMA user_version)
    asi/net.py      jeden klient HTTP;  asi/config.py - jedyne miejsce czytające zmienne ASI_*

**Jedno źródło reguł:** `asi/domain.json` (ważności, wagi, progi werdyktu, odstępy harmonogramu) czytają zarówno
`asi/domain.py`, jak i frontend (import podczas builda), więc UI, raport i alerty nie mogą się rozjechać.

**Etapy skanu** (`asi/scan/pipeline.py: STAGES`): wymagane budują model zasobów (ich błąd = skan `failed`), opcjonalne
wzbogacają wynik (błąd trafia do logu skanu). Nowy etap = funkcja `(ctx, state)` + wpis w `STAGES`.

## Rozwój
    python -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
    .venv/bin/ruff check asi tests && .venv/bin/pytest      # to samo uruchamia CI
    cd frontend && npm ci && npm run build                  # po zmianach w UI; build trafia do static/
    npm run dev                                             # dev server z proxy na :8000

`static/` jest zacommitowany (żeby `run.sh` nie wymagał Node'a); CI sprawdza, że odpowiada źródłom w `frontend/src`.
Zmiana schematu bazy = nowa funkcja na końcu `MIGRATIONS` w `asi/db.py`, nigdy edycja istniejącej.

## Wdrożenie i wycofanie zmian (< 5 min)
1. Przed aktualizacją: kopia bazy (`sqlite3 data/asi.db ".backup data/asi-$(date +%F).db"` albo kopia wolumenu `asi-data`).
2. Aktualizacja: `ASI_VERSION=<nowa> docker compose up -d --build`; weryfikacja: `curl 127.0.0.1:8000/api/health` -> `"status": "ok"`.
3. Wycofanie: `ASI_VERSION=<poprzednia> docker compose up -d` (obraz jest już lokalnie). Jeśli nowa wersja podniosła schemat,
   przywróć kopię z kroku 1 - starsza aplikacja odmówi pracy na nowszej bazie zamiast ją uszkodzić.
4. Awaryjnie bez wdrożenia: `ASI_SCHEDULER=0` zatrzymuje automatyczne skany.

Plan dalszych prac z estymacjami: [docs/ROADMAP.md](docs/ROADMAP.md).
