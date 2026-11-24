# CLAUDE.md

Attack Surface Intelligence (ASI) - PoC: FastAPI (`asi/`) + panel Vite/React (`frontend/`) orkiestrujący
subfinder → dnsx → naabu/nmap → httpx → nuclei. Szczegóły: `README.md`, `docs/architektura.md`, `docs/ROADMAP.md`,
`PRODUCT.md`, `DESIGN.md`.

## Zasady pracy (obowiązkowe)

1. **Pragmatic Programmer** - przy każdym pisaniu lub zmianie kodu najpierw wywołaj skill `pragmatic-programmer`
   (`.claude/skills/pragmatic-programmer`) i stosuj jego zasady (DRY, ortogonalność, małe odwracalne kroki,
   brak "wybitych okien").
2. **Commit + push po każdej zmianie** - po zakończeniu każdej logicznej zmiany: uruchom testy/linter,
   `git add` (konkretne pliki, nigdy `.env`, `*.db`, `data/`, `pass.txt`), `git commit`, `git push` na `origin`.
   Nie zostawiaj niezacommitowanej pracy.
3. **CLAUDE.md jest żywym dokumentem** - po każdej zmianie, która wpływa na strukturę, komendy, konwencje,
   zmienne środowiskowe lub decyzje architektoniczne, zaktualizuj ten plik (i `README.md`, jeśli dotyczy)
   w tym samym commicie. Usuwaj nieaktualne wpisy zamiast dopisywać obok.

## Komendy

    pytest                          # testy (tests/), konfiguracja w pyproject.toml
    ruff check . && ruff format .   # lint (line-length 160, py311)
    bash run.sh                     # serwer ręcznie: http://127.0.0.1:8000
    docker compose up -d --build    # pełne środowisko z narzędziami
    cd frontend && npm ci && npm run build   # panel (npm run dev - proxy /api -> 127.0.0.1:8000)

## Struktura

- `asi/` - backend (api/, scan/, repo/, auth, db, scheduler, report, defectdojo, gvm_scan, ...)
- `asi/nmap/` - nmap bez wejścia/wyjścia: `options` (model i profile), `policy` (bramka NSE), `command`, `parser`, `rules`
  (NSE → ustalenia, tabela); uruchamianie w `asi/scan/nmap_scan.py`, API w `asi/api/nmap.py`. Nowa opcja nmapa = pole
  w `options` + flaga w `command` + kontrolka w `frontend/src/components/NmapOptions.jsx`
- `frontend/` - panel React (Vite); serwer podaje `frontend/dist`, bez niego stary UI z `static/` pod `/legacy`
- `tests/` - pytest; `scripts/` - install_tools, seed_demo, docker_smoke_test; `deploy/`, `lab/` - infrastruktura/lab
- `docs/` - dokumentacja i prezentacje

## Konwencje

- Język: komunikacja, komentarze i dokumentacja po polsku (z diakrytykami); identyfikatory kodu po angielsku.
- Nie commituj sekretów ani plików lokalnych (`.env`, `*.db`, `data/`, `pass.txt`).
- Każdy tekst panelu ma klucz PL i EN w `frontend/src/i18n.jsx`; tytuły i zalecenia własnych ustaleń także w `FINDING_EN`.
- `ASI_NMAP_INTRUSIVE=1` (tylko admin) odblokowuje NSE brute/exploit/dos/fuzzer; `ASI_NMAP_TIMEOUT` - limit uruchomienia [s].
- Skanuj wyłącznie cele, na które jest zgoda (`ASI_ALLOWED_TARGETS`).
