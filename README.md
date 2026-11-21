# Attack Surface Intelligence - PoC

Web UI (FastAPI + panel Vite/React) orkiestrujące narzędzia z Kali/Ubuntu: subfinder → dnsx → naabu/nmap → httpx → (opcjonalnie) nuclei.
Brakujące narzędzie zastępuje fallback w czystym Pythonie. Wynik: graf zasobów, ustalenia z zaleceniami, wynik ryzyka 0-100,
diff względem poprzedniego skanu tego samego celu oraz raport HTML.

## Uruchomienie - Docker (zalecane)
Jedna komenda, bez WSL/Kali/ręcznej instalacji `go install` - wszystkie narzędzia
(nmap, subfinder, dnsx, naabu, httpx, nuclei) są wbudowane w obraz.

    docker compose up -d --build
    docker compose logs asi   # tu jest hasło pierwszego admina, wypisane raz przy starcie
    # -> http://localhost:8000

`network_mode: host` w `docker-compose.yml` wymaga natywnego Dockera na Linuksie (jedyny
sposób, żeby kontener widział realną sieć LAN do skanowania). Na Docker Desktop
(Windows/Mac) usuń tę linię i odkomentuj `ports: ["8000:8000"]` - skanowanie będzie wtedy
ograniczone do tego, co widoczne z wirtualnej maszyny Docker Desktop. Zmienne środowiskowe
(sekcje niżej) ustaw przez plik `.env` obok `docker-compose.yml` albo `environment:` w pliku.

## Panel operacyjny
`/` to panel „co się zmieniło od ostatniego przebiegu i czy to prawda” (React, `frontend/`):
zmiany od przebiegu (A), mapa przestrzeni adresowej z kafelkami /24 i pasmami portów dla małych
zakresów (B), kolejka triage z eksportem do DefectDojo (C), tabela zakresów z oknem skanu jako
budżetem czasu, notatką i przyciskiem uruchom/zatrzymaj (D). Akcje zależą od roli. Pełna obsługa
klawiaturą (`?` pokazuje skróty), PL/EN, motyw ciemny i jasny. Widoki spoza panelu (skan, sygnatury,
harmonogram, użytkownicy) są w starym UI pod `/legacy`.

Obraz Dockera buduje panel sam (etap `node`). Ręcznie: `cd frontend && npm ci && npm run build`
(serwer podaje `frontend/dist`, a bez niego wraca do starego UI). Tryb deweloperski: `npm run dev`
(proxy `/api` → `127.0.0.1:8000`).

Dane demonstracyjne (syntetyczne, oznaczone w notatkach zakresów; nie uruchamiają żadnego skanu):

    ASI_DB=data/demo.db ASI_SECRET_KEY_FILE=data/demo.key python scripts/seed_demo.py --force

## Uruchomienie - ręczne (Ubuntu / WSL, bez Dockera)
    bash scripts/install_tools.sh   # nmap + narzędzia ProjectDiscovery (go install)
    bash run.sh                     # http://127.0.0.1:8000

Zmienne: `ASI_HOST`, `ASI_PORT`, `ASI_DB`, `ASI_ALLOWED_TARGETS=example.com,lab.local` (allowlista;
dla CIDR/IP podaj zakres, np. `10.0.0.0/8`), `ASI_ALLOW_PRIVATE=1` (skanuj też adresy prywatne
znalezione w DNS - adresy podane wprost jako cel/CIDR nigdy nie są tym filtrowane).

### Skala i wydajność
`ASI_MAX_TARGETS` (domyślnie 20000 - twardy limit celów na jeden skan, liczony przed
rozwinięciem CIDR), `ASI_MAX_WORKERS` (domyślnie 4 - ile skanów/jobów naraz zamiast
dawnej kolejki po jednym), `ASI_SCAN_RATE` (domyślnie 300 - pakiety/s dla naabu/nmap,
nadpisywalne per-skan przez pole `rate_limit` w żądaniu, 1-10000).

### RBAC i szyfrowanie
Przy pierwszym uruchomieniu powstaje użytkownik `admin` z losowym hasłem wypisanym raz w logu.
4 role: `read`, `read_modify`, `add_remove_modify`, `admin`. `ASI_COOKIE_SECURE=1` - ustaw, gdy
aplikacja stoi za reverse proxy terminującym TLS (domyślnie wyłączone, bo PoC chodzi po HTTP).
`ASI_SECRET_KEY` (albo plik `ASI_SECRET_KEY_FILE`, domyślnie `data/secret.key`) - klucz Fernet do
szyfrowania `findings.detail`/`scans.log`/`assets.data`; bez niego generowany i trwale zapisany
automatycznie przy pierwszym starcie.

### DefectDojo (opcjonalnie)
Eksport findingów skanu jako "Generic Findings Import". `ASI_DEFECTDOJO_URL`,
`ASI_DEFECTDOJO_API_KEY` (token z profilu usera DefectDojo), opcjonalnie `ASI_DEFECTDOJO_PRODUCT`
i `ASI_DEFECTDOJO_PRODUCT_TYPE` (domyślnie "Attack Surface Intelligence" - tworzone automatycznie
po stronie DefectDojo, jeśli nie istnieją).

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

## Dokumentacja
- `docs/architektura.md` - architektura, model danych, mapowanie na wymagania specyfikacji AGH, znane zaległości.
- `docs/screnariusz.md` - modułowy scenariusz prezentacji/demo.
- `docs/openvas.md` - opcjonalna integracja z OpenVAS/GVM.

## Bezpieczeństwo
- Skanuj wyłącznie zasoby, do których masz zgodę (UI wymaga potwierdzenia). Bezpieczny cel testowy: `scanme.nmap.org`.
- API uruchamia skany - nie wystawiaj go publicznie bez uwierzytelnienia (reverse proxy + auth). Zob. `deploy/asi.service`.
- Cel jest walidowany, komendy działają bez powłoki (brak command injection).
