# Attack Surface Intelligence - PoC

Web UI (FastAPI + vanilla JS) orkiestrujące narzędzia z Kali/Ubuntu: subfinder → dnsx → naabu/nmap → httpx → (opcjonalnie) nuclei.
Brakujące narzędzie zastępuje fallback w czystym Pythonie. Wynik: graf zasobów, ustalenia z zaleceniami, wynik ryzyka 0-100,
diff względem poprzedniego skanu tego samego celu oraz raport HTML.

## Uruchomienie (Ubuntu / WSL)
    bash scripts/install_tools.sh   # nmap + narzędzia ProjectDiscovery (go install)
    bash run.sh                     # http://127.0.0.1:8000

Zmienne: `ASI_HOST`, `ASI_PORT`, `ASI_DB`, `ASI_ALLOWED_TARGETS=example.com,lab.local` (allowlista),
`ASI_ALLOW_PRIVATE=1` (skanuj też adresy prywatne/loopback znalezione w DNS).

### OpenVAS/GVM (opcjonalnie, głęboki skan w tle)
Dodatkowy, wolny etap (minuty-godziny) uruchamiany w osobnym wątku, poza główną kolejką skanów -
nie blokuje wyniku szybkiego pipeline'u. Wymaga działającego Greenbone Community Edition
(gvmd) osiągalnego po GMP przez gołe TCP (zob. `docs/openvas.md` - tam opis stawiania GVM
w osobnej WSL/Ubuntu przez Docker Compose + mostek TCP<->unix socket, bo oficjalny kontener
GVM wystawia GMP tylko po unix sockecie).

Zmienne: `ASI_GVM_HOST` (adres IP hosta z GVM; brak = funkcja wyłączona), `ASI_GVM_PORT` (domyślnie 9390),
`ASI_GVM_USERNAME` (domyślnie `admin`), `ASI_GVM_PASSWORD`, `ASI_GVM_SCAN_CONFIG` (domyślnie "Full and fast"),
`ASI_GVM_SCANNER` (domyślnie "OpenVAS Default"), `ASI_GVM_PORT_LIST` (domyślnie "All IANA assigned TCP and UDP"),
`ASI_GVM_MAX_WAIT` (sekundy, domyślnie 3600).

## Bezpieczeństwo
- Skanuj wyłącznie zasoby, do których masz zgodę (UI wymaga potwierdzenia). Bezpieczny cel testowy: `scanme.nmap.org`.
- API uruchamia skany - nie wystawiaj go publicznie bez uwierzytelnienia (reverse proxy + auth). Zob. `deploy/asi.service`.
- Cel jest walidowany, komendy działają bez powłoki (brak command injection).
