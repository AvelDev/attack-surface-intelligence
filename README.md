# Attack Surface Intelligence - PoC

Web UI (FastAPI + vanilla JS) orkiestrujące narzędzia z Kali/Ubuntu: subfinder → dnsx → naabu/nmap → httpx → (opcjonalnie) nuclei.
Brakujące narzędzie zastępuje fallback w czystym Pythonie. Wynik: graf zasobów, ustalenia z zaleceniami, wynik ryzyka 0-100,
diff względem poprzedniego skanu tego samego celu oraz raport HTML.

## Uruchomienie (Ubuntu / WSL)
    bash scripts/install_tools.sh   # nmap + narzędzia ProjectDiscovery (go install)
    bash run.sh                     # http://127.0.0.1:8000

Zmienne: `ASI_HOST`, `ASI_PORT`, `ASI_DB`, `ASI_ALLOWED_TARGETS=example.com,lab.local` (allowlista),
`ASI_ALLOW_PRIVATE=1` (skanuj też adresy prywatne/loopback znalezione w DNS).

## Bezpieczeństwo
- Skanuj wyłącznie zasoby, do których masz zgodę (UI wymaga potwierdzenia). Bezpieczny cel testowy: `scanme.nmap.org`.
- API uruchamia skany - nie wystawiaj go publicznie bez uwierzytelnienia (reverse proxy + auth). Zob. `deploy/asi.service`.
- Cel jest walidowany, komendy działają bez powłoki (brak command injection).
