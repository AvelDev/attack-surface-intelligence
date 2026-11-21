# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack
React (wybór użytkownika, zastępuje dotychczasowy vanilla JS). Backend: FastAPI serwujący `static/`. Decyzja o sposobie buildu: Vite + React, wynik budowany do `static/`, tak aby `run.sh` nie wymagał Node'a na serwerze.

## Users
Pracownik instytucji publicznej / firmy państwowej (budżetówka), nie informatyk. Wpisuje adres strony swojej instytucji, dostaje ocenę w jednym zdaniu, listę rzeczy do naprawy i raport dla przełożonego lub informatyka. Szczegóły techniczne (mapa, tabela zasobów, log, CSV/JSON) są w złożonej sekcji „Dla informatyka”.

## Product Purpose
Orkiestruje narzędzia (subfinder, dnsx, naabu/nmap, httpx, nuclei; fallback w Pythonie) i zamienia wynik w graf zasobów, ustalenia z zaleceniami, wynik ryzyka 0-100, diff względem poprzedniego skanu i raport HTML. Sukces: operator szybko widzi, co jest wystawione, co się zmieniło i co naprawić najpierw.

## Positioning
Jedno narzędzie łączące mapę powierzchni ataku, priorytetyzację ryzyka i diff między skanami tego samego celu, z fallbackiem gdy brakuje narzędzi Kali.

## Operating Context
Uruchamiane lokalnie (Ubuntu/WSL/Kali), `http://127.0.0.1:8000`. Skany są długie i asynchroniczne (queued/running, odpytywanie co 2 s). Dostęp do internetu nie jest gwarantowany (vis-network z CDN ma fallback tabel).

## Capabilities and Constraints
- API: `/api/tools`, `/api/scans` (POST/GET), `/api/scans/{id}` (GET/DELETE), export JSON/CSV, raport HTML, `/api/schedules` (cykliczne skany), `/api/alerts` (powiadomienia).
- UI wymaga potwierdzenia zgody właściciela przed skanem; opcjonalny nuclei.
- Interfejs po polsku. Wagi: krytyczne, wysokie, średnie, niskie, info.
- Układ: jedna kolumna (max ok. 62rem), dwa ekrany: start (formularz + historia) i wynik (postęp / ocena / co zrobić najpierw / zmiany / „Dla informatyka”). Routing przez hash `#/sprawdzenie/ID`.

## Brand Commitments
Wymóg użytkownika (zmiana stylu): obsłuży to osoba z budżetówki. Jasny, urzędowy, bardzo czytelny interfejs, prosty polski język bez żargonu, jeden wąski widok zamiast układu IDE. Poprzedni styl (ciemny, VS Code) porzucony.

## Evidence on Hand
Brak logo, testimoniali ani danych referencyjnych. Bezpieczny cel testowy: `scanme.nmap.org`.

## Product Principles
1. Gęstość i precyzja ponad dekorację: operator widzi dużo naraz.
2. Zgoda na skan jest zawsze jawna.
3. Ustalenia są uporządkowane wg ryzyka, każde ze źródłem i zaleceniem.
4. Zmiana względem poprzedniego skanu jest pierwszorzędną informacją.
5. Działa bez internetu i bez brakujących narzędzi.

## Accessibility & Inclusion
Wysoki kontrast, duża czcionka (ok. 18 px), cele dotykowe min. ok. 44 px, waga zawsze tekstem i kształtem (nie tylko kolorem), pełna obsługa klawiaturą, widoczny fokus; wzorzec zgodny z WCAG 2.1 AA (obowiązek dla podmiotów publicznych).
