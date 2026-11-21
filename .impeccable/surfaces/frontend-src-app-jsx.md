---
version: 1
slug: "frontend-src-app-jsx"
primary_target: "frontend/src/App.jsx"
related_targets: []
---

# Surface: Przegląd (dashboard)

Mode: Operate. Target: `frontend/src/` (Vite + React), route `/`.
Audience: technicy zespołu bezpieczeństwa (CBI AGH), laptop/monitor, poranny przegląd po przebiegach. Jury testuje na labie (`lab/`, jeden host, kilkanaście usług).
Job: odpowiedzieć bez klikania „co się zmieniło od ostatniego przebiegu i czy to prawda”; z miejsca: triage zmian (trwały między skanami), eksport zaznaczonych do DefectDojo, uruchom/wstrzymaj skan zakresu (wg roli).
Scale: od 1 hosta × 15 usług do >10 000 IP, 1–30 zakresów. States: first-run, pierwszy przebieg bez bazy, skan w toku / czeka na okno / przerwany przez okno / zatrzymany, loading, błąd API, rola read, zero zmian.
Out of scope: brak; pozostałe ekrany (skany, znaleziska, sygnatury, harmonogram, integracje, użytkownicy) są w React pod `#/<ekran>`, w tej samej gramatyce modułów. Command Center 3D zostaje osobną stroną.
Open decisions resolved: pewność = liczba przebiegów potwierdzających (k/N); `static/` zostaje jako `/legacy` do czasu pełnej migracji.

## Direction contract

THESIS: Ekran DataV przy biurku: gramatyka big-screen (moduły w ramkach z narożnikami i literami A–D, kropkowy wireframe, pasek liczników) zagęszczona do pracy operatora; odmawia rzędu kart KPI + donut + world map.
OWN-WORLD: Czarne tło, jasnoszary atrament, szarości hairline 1px; pomarańcz wyłącznie = zmiana, czerwień wyłącznie = krytyczne; narożniki HUD na modułach, literowe tagi A/B/C/D w odwróconym kolorze; condensed display dla nagłówków modułów, workhorse sans dla UI, mono dla adresów i liczb. Tryb jasny jako odwrócenie atramentu na papier.
STORY: Operator widzi liczbę zmian z historią i momentem onsetu, gdzie w przestrzeni adresowej wystąpiły, przechodzi kolejkę triage z klawiatury, oznacza, eksportuje, uruchamia lub wstrzymuje zakres.
FIRST VIEWPORT: Lewa szyna 64px; górny pasek (marka, filtr zakresu, ostatni przebieg, PL/EN, motyw, użytkownik·rola). Rząd: A „Zmiany od przebiegu” 320px (duża liczba, sparkline z onsetem, wiersze + − ~ ⇅ ▲) | B „Przestrzeń adresowa” elastyczny (każda /24 jako płytka 16×16 kropek = adresy; przy ≤16 hostach kolumny portów; pomarańczowe/czerwone iglice nad zmianami; suwak przebiegów u dołu) | C „Kolejka triage” 360px. Pod spodem D: tabela zakresów (hosty, stan, okno jako budżet czasu z przekroczeniem, ostatnia zmiana, notatka, akcja). Stopka: pasek liczników.
FORM: kandydat 7/7 z listy ugruntowanej (literalny DataV z referencji użytkownika), podniesiony o: budżet okna (j-card), stałe meble zakresu (katalog), rejestracja przebiegów w identycznej skali (folio), jeden suwak czasu przemapowujący całe pole (specymen). Ruch znakowy: kropkowa mapa adresów z iglicami zmian. seed:ed8bc3ab2bb8e213
FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
