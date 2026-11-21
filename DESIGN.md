---
name: ASI · Attack Surface Intelligence
description: Ekran operatora w gramatyce DataV, zagęszczony do pracy przy biurku; pomarańcz znaczy zmianę, czerwień znaczy krytyczne.
colors:
  bg: "#050607"
  bg-2: "#0a0c0e"
  bg-3: "#111417"
  ink: "#dadde0"
  ink-2: "#a4abb2"
  ink-3: "#80878f"
  line: "#23272c"
  line-2: "#363b41"
  dot: "#2a2f35"
  dot-live: "#b9bec3"
  change: "#ff9a2e"
  change-ink: "#ffb05c"
  crit: "#ff5c61"
  ok: "#8fd0a8"
  focus: "#e8ebee"
  bg-light: "#f2f2ef"
  bg-2-light: "#e8e8e4"
  bg-3-light: "#dfdfda"
  ink-light: "#121416"
  ink-2-light: "#3b4147"
  ink-3-light: "#565d64"
  line-light: "#cfd1cc"
  line-2-light: "#b3b6b1"
  dot-light: "#cdd0cb"
  dot-live-light: "#2b3036"
  change-light: "#c46200"
  change-ink-light: "#994c00"
  crit-light: "#b4232a"
  ok-light: "#276a42"
  focus-light: "#111417"
typography:
  brand:
    fontFamily: "Saira Condensed, Geist Sans, sans-serif"
    fontSize: "26px"
    fontWeight: 700
    lineHeight: 1
    letterSpacing: "0.16em"
  display:
    fontFamily: "Saira Condensed, Geist Sans, sans-serif"
    fontSize: "1.5rem"
    fontWeight: 600
    lineHeight: 1.05
    letterSpacing: "0.015em"
  headline-number:
    fontFamily: "Geist Mono, ui-monospace, Cascadia Mono, monospace"
    fontSize: "3rem"
    fontWeight: 500
    lineHeight: 1
    letterSpacing: "-0.02em"
    fontFeature: "tnum"
  body:
    fontFamily: "Geist Sans, ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.8125rem"
    fontWeight: 400
    lineHeight: 1.45
    fontFeature: "ss01, cv11"
  label:
    fontFamily: "Geist Sans, ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 400
    lineHeight: 1.3
  table-head:
    fontFamily: "Geist Sans, ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 500
    letterSpacing: "0.08em"
  mono:
    fontFamily: "Geist Mono, ui-monospace, Cascadia Mono, monospace"
    fontSize: "0.75rem"
    fontWeight: 400
    fontFeature: "tnum"
rounded:
  none: "0px"
  dot: "50%"
spacing:
  s-1: "4px"
  s-2: "8px"
  s-3: "12px"
  s-4: "16px"
  s-5: "24px"
  s-6: "32px"
  rail: "64px"
  top: "52px"
  tick: "32px"
components:
  button:
    backgroundColor: "transparent"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
    padding: "6px 12px"
    typography: "{typography.body}"
  button-hover:
    backgroundColor: "{colors.bg-3}"
  button-primary:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.bg}"
    rounded: "{rounded.none}"
    padding: "6px 12px"
  button-primary-hover:
    backgroundColor: "{colors.ink-2}"
  button-danger:
    backgroundColor: "transparent"
    textColor: "{colors.crit}"
    rounded: "{rounded.none}"
    padding: "6px 12px"
  segment-on:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.bg}"
    padding: "4px 9px"
  module-tag:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.bg}"
    typography: "{typography.mono}"
    padding: "3px 6px"
  input:
    backgroundColor: "{colors.bg-2}"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
    padding: "8px 10px"
  chip:
    backgroundColor: "transparent"
    textColor: "{colors.ink-2}"
    rounded: "{rounded.none}"
    padding: "0 6px"
    height: "18px"
  toast:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.bg}"
    padding: "10px 10px 10px 14px"
    width: "440px"
  toast-error:
    backgroundColor: "{colors.bg}"
    textColor: "{colors.crit}"
---

# Design System: ASI · Attack Surface Intelligence

## Overview

**Creative North Star: "Ekran DataV przy biurku"**

Gramatyka ekranów big-screen (moduły w ramkach z narożnikami HUD, literowe znaczniki A–D, kropkowy wireframe, pasek liczników u dołu) przeniesiona na laptop operatora i zagęszczona do pracy z bliska. Ekran ma jedno zadanie: pokazać bez klikania, co się zmieniło od ostatniego przebiegu i gdzie w przestrzeni adresowej. Wszystko, co nie jest zmianą, jest jasnoszarym atramentem na czerni.

Gęstość jest wysoka, ale uporządkowana: tekst UI 13px, meta 12px, hairline 1px wszędzie. Głębię dają ramki i odcienie tła, nie cienie. Tryb ciemny jest domyślny; jasny to odwrócenie atramentu na papier (ciepła, złamana biel), z osobno dobranymi tonami tak, żeby mały tekst trzymał WCAG 2.2 AA w obu motywach.

Odrzucone: rząd kart KPI z donutem i mapą świata, zaokrąglone karty, akcenty z bocznego paska, kolor jako jedyny nośnik stanu.

**Key Characteristics:**
- Czarne tło, jasnoszary atrament, szare hairline 1px, zero zaokrągleń.
- Pomarańcz wyłącznie = zmiana; czerwień wyłącznie = krytyczne / przekroczone / błąd.
- Moduły w ramkach z narożnikami i odwróconym znacznikiem literowym.
- Stan zawsze kształtem (kropka, romb, pierścień, półwypełnienie, długość iglicy) i etykietą, nigdy samym kolorem.
- Condensed display tylko w nagłówkach modułów i znaku; Geist Sans dla UI; Geist Mono wyłącznie dla adresów i liczb.

## Colors

Monochromatyczny atrament na czerni plus dwa sygnały o ściśle przypisanym znaczeniu. Każdy token ma odpowiednik jasny (`-light`), przełączany atrybutem `data-theme` na `:root`.

### Primary
- **Sygnałowy Pomarańcz Zmiany** (`change`; jasny `change-light`): kropki, romby, pierścienie i iglice zmienionych adresów, ikony rodzajów zmian, znacznik onsetu na historii, stan „w toku / w kolejce”. Tylko znaki graficzne i duże kształty.
- **Atrament Zmiany** (`change-ink`; jasny `change-ink-light`): ten sam sygnał w wersji tekstowej, dla etykiet i krótkich wyróżnień tekstem (kontrast AA na małym tekście).

### Secondary
- **Alarmowa Czerwień** (`crit`; jasny `crit-light`): wyłącznie krytyczne znaleziska, przekroczony budżet okna, skan przerwany przez okno lub nieudany, błąd API i formularza. Tło ostrzeżeń jako półprzezroczysty wash (12% / 8%).

### Tertiary
- **Stonowana Zieleń Statusu** (`ok`; jasny `ok-light`): jedynie tekst statusu triage (zamknięte / potwierdzone). Nie służy do wyróżniania ani do wykresów.

### Neutral
- **Czerń Ekranu** (`bg`): tło aplikacji i modułów.
- **Druga Warstwa** (`bg-2`): szyna, pasek liczników, pola formularzy, hover wiersza.
- **Trzecia Warstwa** (`bg-3`): wiersz wybrany i aktywny, tło szkieletów ładowania, tor paska budżetu.
- **Jasny Atrament** (`ink`): tekst główny, aktywne elementy, przycisk główny, znacznik modułu, pierścień zaznaczenia.
- **Atrament Drugorzędny** (`ink-2`): tytuły pomocnicze, narożniki ramek, ikony neutralne, wypełnienie paska budżetu.
- **Atrament Meta** (`ink-3`): meta, daty, nagłówki tabel, nieaktywne linki szyny (>= 4.5:1 na `bg`).
- **Hairline** (`line`, `line-2`): ramki modułów, separatory wierszy (kreskowane), obramowania kontrolek i hover.
- **Kropka Pusta / Kropka Żywa** (`dot`, `dot-live`): adres bez hosta i żywy host na mapie adresów oraz w polach kropkowych.
- **Fokus** (`focus`): obrys `:focus-visible`.

### Named Rules
**Reguła Pomarańczu = Zmiana.** Pomarańcz oznacza zmianę i nic więcej. Fokus, zaznaczenie, stan aktywny i wybrany używają atramentu (obrys 2px w `focus`, pierścień 1px inset w `ink`), nigdy pomarańczu. Jedyny wyjątek to litera „S” w znaku „A S I” (logo).

**Reguła Czerwieni = Krytyczne.** Czerwień pojawia się tylko przy krytycznym, przekroczonym lub nieudanym. Ostrzeżenie „do sprawdzenia” to nie czerwień.

**Reguła Kształtu przed Kolorem.** Żaden stan nie jest kodowany samym kolorem: kropka = żywy / nowy, romb = zmieniony, pierścień = zniknął, półwypełnienie = flapping, długość iglicy = waga; na listach ikona plus etykieta.

**Reguła Dwóch Motywów AA.** Mały tekst trzyma WCAG 2.2 AA w obu motywach; w jasnym dlatego `ink-3-light`, `change-ink-light` i `ok-light` są ciemniejsze niż proste odwrócenie.

## Typography

**Display Font:** Saira Condensed (600, 700; fallback Geist Sans)
**Body Font:** Geist Sans (400, 500, 600; fallback system-ui)
**Label/Mono Font:** Geist Mono (400, 500; fallback Cascadia Mono, monospace)

**Character:** Zwężony, techniczny display nadaje modułom charakter tablicy sterowniczej; Geist Sans robi całą robotę roboczą; Geist Mono z cyframi tabelarycznymi trzyma adresy i liczby w równych kolumnach. Wszystkie fonty są self-hosted (@fontsource), bez CDN.

### Hierarchy
- **Brand** (700, 26px, 1, rozstrzelenie 0.16em): znak „A S I” w pasku górnym; 44px na ekranie logowania.
- **Display** (600, 24px, 1.05): tytuły modułów A–D; 20px dla pustych stanów i karty logowania.
- **Headline-number** (Mono 500, 48px, 1, -0.02em): łączna liczba zmian w module A.
- **Body** (400, 13px, 1.45): cały tekst UI, wiersze list i tabel, przyciski.
- **Label** (400, 12px): meta, daty, legendy, pasek liczników, chipy.
- **Table-head** (500, 12px, wersaliki, 0.08em): wyłącznie nagłówki kolumn tabeli.
- **Mono** (400, 12–16px, tnum): adresy IP, CIDR, porty, liczniki, wartości liczbowe.

### Named Rules
**Reguła Mono dla Maszyny.** Monospace tylko dla adresów i liczb. Czasy i daty pisane prozą („2 godz. temu”, „wczoraj 03:10”) idą w Geist Sans.

**Reguła Jednego Display.** Saira Condensed występuje tylko w znaku i tytułach modułów; nigdy w treści, przyciskach ani etykietach.

## Layout

Powłoka to siatka: lewa szyna 64px (`rail`) i kolumna z paskiem górnym 52px (`top`), polem dashboardu i paskiem liczników 32px (`tick`). Na pulpicie pole dashboardu to trzy kolumny `300px | elastyczna | 380px` (A zmiany, B przestrzeń adresowa, C kolejka triage) i pełnoszeroki rząd D (tabela zakresów) pod spodem, z odstępem 16px i marginesem 16/24px.

Rytm odstępów: 4 / 8 / 12 / 16 / 24 / 32px. Wnętrze modułu 14px × 16px; listy i tabele wychodzą do krawędzi modułu (ujemny margines -16px), żeby hover i zaznaczenie wiersza sięgały ramki.

Responsywność:
- **≤ 1279px:** dwie kolumny, układ `A C / B B / D D`; moduły trzymają stałe wysokości (A i C 540px, B 520px), pole przewija się w całości; znika „ostatni przebieg” z paska.
- **≤ 759px:** jedna kolumna `A / C / B / D`, szyna staje się poziomym paskiem ikon u góry, filtr zakresu na pełną szerokość, pasek liczników zawija się; na ekranach dotykowych akcje wiersza triage są widoczne stale.

## Elevation & Depth

System jest płaski. Głębię niosą hairline 1px i trzy odcienie tła (`bg` → `bg-2` → `bg-3`). Cień istnieje tylko dla nakładek unoszących się nad treścią: toastu i dialogu skrótów.

### Shadow Vocabulary
- **Nakładka** (`box-shadow: 0 12px 32px rgba(0,0,0,0.55)`; jasny `0 12px 28px rgba(18,20,22,0.16)`): toast i dialog. Nigdzie indziej.

### Named Rules
**Reguła Płaskiego Modułu.** Moduły, wiersze i kontrolki nie mają cienia. Stan pokazuje ramka lub odcień tła, nie uniesienie.

## Shapes

Wszystko jest prostokątne (promień 0). Ramka modułu to hairline 1px w `line` z dwoma narożnikami HUD 11×11px w `ink-2` (lewy górny i prawy dolny) oraz znacznikiem literowym w odwróconym kolorze w prawym górnym rogu. Ten sam motyw narożników w mniejszej skali (6px w `ink`) oznacza bieżącą pozycję szyny. Separatory wierszy list są kreskowane 1px; tabela używa linii ciągłych.

Okręgi (50%) występują wyłącznie jako znaki danych: kropki hostów, pierścienie zniknięć, punkty legendy. Romb (kwadrat obrócony o 45°) to znak zmiany lub stanu krytycznego. Przekroczenie budżetu okna oznacza ukośne kreskowanie 135° w `crit`.

### Named Rules
**Reguła Ramki, nie Karty.** Brak zaokrąglonych kart. Kontener to hairline z narożnikami HUD albo nic.

## Components

### Buttons
Rzeczowe, prostokątne, bez ozdób.
- **Shape:** promień 0, ramka 1px `line-2`, padding 6px 12px (mały: 3px 9px, 12px).
- **Domyślny:** przezroczysty, tekst `ink`, 500. Hover: ramka `ink-2`, tło `bg-3`, 150ms.
- **Główny:** wypełnienie `ink`, tekst `bg`; hover `ink-2`.
- **Niebezpieczny:** tekst `crit`, ramka czerwień zmieszana z `line`; hover wash `crit` i pełna ramka.
- **Ikonowy:** 30×30px (22px mały), bez ramki w spoczynku, ramka `line-2` przy hover.
- **Fokus:** globalny obrys 2px `focus`, offset 2px.

### Segmented control
Przełączniki PL/EN, motywu i filtrów: ramka 1px `line-2`, przyciski 12px, 600, 0.06em; wybrany segment wypełniony `ink` z tekstem `bg`.

### Chips
- **Style:** ramka 1px `line-2`, tekst `ink-2`, 12px, wysokość 18px, bez tła.

### Cards / Containers (moduł HUD)
- **Corner Style:** 0, narożniki HUD 11px w `ink-2`.
- **Background:** `bg`.
- **Shadow Strategy:** brak (patrz Elevation & Depth).
- **Border:** 1px `line`.
- **Internal Padding:** 14px 16px.
- **Nagłówek:** tytuł display 24px, obok meta 12px w `ink-3`, akcje do prawej; znacznik litery A–D w mono 600 12px, odwrócony (`ink` / `bg`).

### Inputs / Fields
- **Style:** tło `bg-2`, ramka 1px `line-2`, promień 0, tekst 14px; etykieta 12px `ink-2` nad polem.
- **Hover:** ramka `ink-3`.
- **Focus:** obrys 2px `focus` bez odsunięcia.
- **Error:** komunikat w `crit` pod formularzem.

### Navigation (szyna)
Ikony 40×40px w `ink-3`; hover i bieżąca pozycja: `ink` z ramką `line-2`, bieżąca dodatkowo z narożnikami HUD 6px w `ink`. Podpowiedź w odwróconym kolorze (`ink` / `bg`) wysuwa się w prawo (120ms). Na telefonie szyna staje się poziomym paskiem bez podpowiedzi.

### Wiersze list i tabel
Hover: `bg-2` (lub `bg-3` w module A). Wybrany / aktywny / fokus: tło `bg-3` i pierścień inset 1px `ink`. Zamknięty wpis triage: przekreślenie w `line-2` i tekst `ink-3`. Akcje wiersza triage (28×28px) pojawiają się przy hover i fokusie.

### Pewność (pipsy)
Słupki 4×8px z ramką `ink-3`; potwierdzone przebiegi wypełnione `ink-2`, obok liczba k/N. Pewność nigdy nie jest pomarańczowa.

### Mapa adresów (komponent sygnaturowy)
Każda /24 to płytka 16×16 kropek rysowana na canvasie (kropka = adres; `dot` pusty, `dot-live` żywy host). Nad zmienionymi adresami wyrastają iglice z gradientem do przezroczystości: pomarańczowe dla zmian, dłuższe i czerwone dla krytycznych. Przy ≤ 16 hostach mapa przechodzi w pasma portów: kolumna 68px na port, z kropką stanu, numerem portu i usługą. Pod mapą legenda kształtów i suwak przebiegów (kwadratowe znaczniki 9px, wybrany wypełniony `ink`), który przemapowuje całe pole.

### Budżet okna
Pasek 6px z ramką `line` i wypełnieniem `ink-2` pokazuje zużycie okna czasowego. Przekroczenie: ramka i wypełnienie `crit`, tor kreskowany 135°, tekst w `crit`.

### Pasek liczników
Stopka 32px na `bg-2`, etykiety 12px `ink-3`, wartości `ink` 500, każdy licznik z kwadratowym znakiem 8px (neutralny, zmiana, romb krytyczny).

### Toast
Informacyjny: odwrócony (`ink` / `bg`), znika po 5s. Błąd: tło `bg`, ramka i tekst `crit`, `role="alert"`, zostaje do zamknięcia przez operatora. Wjazd 220ms z 8px.

### Ruch
Jedna krzywa `cubic-bezier(0.16, 1, 0.3, 1)`; hover i stany 150ms, podpowiedzi 120ms, toast 220ms, wzrost iglic portów 650ms. `prefers-reduced-motion` wyłącza wszystkie przejścia i animacje.

## Do's and Don'ts

### Do:
- **Do** rezerwuj `change` dla zmian (nowe, zniknięte, zmienione, flapping, onset, skan w toku), a `change-ink` dla tekstu o zmianie.
- **Do** oznaczaj fokus obrysem 2px `focus` (offset 2px), a zaznaczenie i stan aktywny pierścieniem inset 1px `ink` na tle `bg-3`.
- **Do** koduj stan kształtem: kropka = żywy / nowy, romb = zmieniony, pierścień = zniknął, półwypełnienie = flapping, długość iglicy = waga; na listach ikona plus etykieta.
- **Do** opakowuj każdy moduł ramką hairline z narożnikami HUD i odwróconym znacznikiem literowym.
- **Do** pisz adresy, porty i liczby w Geist Mono z cyframi tabelarycznymi; czasy prozą w Geist Sans.
- **Do** zostawiaj komunikaty o błędach na ekranie, aż operator je zamknie.
- **Do** sprawdzaj kontrast małego tekstu (AA) w obu motywach przy każdym nowym tokenie.

### Don't:
- **Don't** używaj pomarańczu do fokusu, zaznaczenia, aktywnej zakładki ani dekoracji; jedyny wyjątek to „S” w znaku „A S I”.
- **Don't** używaj czerwieni do niczego poza krytycznym, przekroczonym budżetem i błędem.
- **Don't** przekazuj stanu samym kolorem.
- **Don't** stosuj akcentów z bocznego paska (kolorowa krawędź z lewej strony wiersza lub karty).
- **Don't** zaokrąglaj kontenerów ani nie buduj kart z cieniem; cień tylko dla toastu i dialogu.
- **Don't** pisz prozy ani etykiet w monospace.
- **Don't** wprowadzaj rzędu kart KPI, donutów ani mapy świata.
