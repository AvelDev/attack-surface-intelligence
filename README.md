# Attack Surface Intelligence - PoC

Web UI (FastAPI + vanilla JS) orkiestrujące narzędzia z Kali/Ubuntu: subfinder → dnsx → naabu/nmap → httpx → (opcjonalnie) nuclei.
Brakujące narzędzie zastępuje fallback w czystym Pythonie. Wynik: graf zasobów, ustalenia z zaleceniami, wynik ryzyka 0-100,
diff względem poprzedniego skanu tego samego celu oraz raport HTML.

## Uruchomienie (Ubuntu / WSL)
    bash scripts/install_tools.sh   # nmap + narzędzia ProjectDiscovery (go install)
    bash run.sh                     # http://127.0.0.1:8000

Zmienne: `ASI_HOST`, `ASI_PORT`, `ASI_DB`, `ASI_ALLOWED_TARGETS=example.com,lab.local` (allowlista),
`ASI_ALLOW_PRIVATE=1` (skanuj też adresy prywatne/loopback znalezione w DNS).

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

## Frontend (React + Vite)
Źródła w `frontend/`, build trafia do `static/` (zacommitowany, więc `run.sh` nie wymaga Node'a).
    cd frontend && npm install && npm run build     # po zmianach w UI
    npm run dev                                     # dev server z proxy na :8000
