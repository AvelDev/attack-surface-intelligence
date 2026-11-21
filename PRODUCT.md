# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Backend bez zmian: Python/FastAPI + SQLite (WAL), narzędzia w obrazie Docker (nmap, subfinder, dnsx, naabu, httpx, nuclei) z fallbackami w Pythonie.

Frontend: **Vite + React** (decyzja użytkownika z 2026-11-21). Zastępuje obecne `static/index.html` i `static/command_center.html` (vanilla JS, vis-network, Three.js). Build ma wejść do multi-stage `Dockerfile`, tak żeby `docker compose up -d --build` dalej było jedynym krokiem uruchomienia (łatwość uruchomienia jest kryterium oceny). Pozostałości w `frontend/` (same `node_modules` po Vite, bez źródeł) nie są źródłem prawdy.

## Users

Zespół bezpieczeństwa: Centrum Bezpieczeństwa Informacji AGH (monitorowanie sieci, obsługa incydentów, testy penetracyjne) i analogiczne zespoły innych uczelni lub partnerów. Na co dzień zajmują się sieciami i pentestingiem (red teaming).

Wszystkie cztery role RBAC (`read`, `read_modify`, `add_remove_modify`, `admin`) mają **technicy**. Nawet rola „Odczyt” to analityk albo pentester, nie kierownictwo. Żargonu (CIDR, flapping, finding, banner, CMS fingerprint) nie trzeba tłumaczyć.

Główne zadanie: cyklicznie skanować rozległą infrastrukturę (ponad 10 000 adresów IP), rozumieć, co faktycznie działa pod każdym adresem, i wychwytywać, co się zmieniło między przebiegami. Następnie robić triage znalezisk i eksportować wybrane do DefectDojo.

Drugi odbiorca w najbliższym czasie: jury CBI AGH (co najmniej 3 specjalistów), które testuje prototyp w labie (co najmniej dwa przebiegi skanu, edycja i import znalezisk, rozgraniczenie ról) i ogląda prezentację z demo na żywo.

## Product Purpose

Prototyp systemu do discovery scan dużej infrastruktury. Wczytuje IP, CIDR i domeny (formularz, CSV, JSON), bezpiecznie skanuje (wielowątkowo, z limitem tempa, w oknach czasowych), wykrywa aktywne hosty, usługi, szczegóły HTTP/HTTPS (tytuł, kod, nagłówki, ciasteczka, certyfikat TLS, przekierowania), technologie (CMS, framework, serwer aplikacyjny, IoT) oraz staging i panele administracyjne. Porównuje przebiegi i oznacza usługi nowe, znikające i zmienione.

Sukces oznacza:
1. W konkursie: wygrana według wag oceny. Discovery 30%, jakość, dokumentacja, prezentacja, uruchomienie, import/eksport i DefectDojo 20%, bezpieczeństwo i czytelność dashboardu 15%, zmiany w czasie i hosty niestabilne 15%, fingerprinting i sygnatury 10%, RBAC i ochrona danych 10%.
2. Po konkursie: wdrożenie i dalszy rozwój w CBI AGH (zwycięzcy przenoszą prawa majątkowe na AGH) oraz udostępnianie narzędzia innym uczelniom.

Źródło prawdy o zakresie: `docs/AGH - Pełna treść zadania konkursowego.pdf`. Funkcji spoza specyfikacji nie dodajemy (np. Shodan, CISA KEV, NVD).

## Positioning

ASI łączy cztery rzeczy, których SecureCodeBox ani goły nmap nie dają razem:

1. **Zmiany w czasie i hosty niestabilne.** ASI odpowiada na pytanie „co się zmieniło i czy to prawda”, nie tylko „co jest otwarte”: diff nowe/zniknięte/zmienione, `flapping_assets`, `confirmed_offline` (nieobecny w co najmniej 2 kolejnych skanach), pewność wyniku.
2. **Priorytet analityczny („ciekawość”).** Panel administracyjny, staging, stary komponent, nietypowy baner czy interesujące ciasteczko wypływają na górę. Operator nie przegląda 10 000 wierszy.
3. **Jedno polecenie, wszystko w środku.** `docker compose up` i wszystkie narzędzia są w obrazie, każde z fallbackiem w czystym Pythonie.
4. **Bezpieczeństwo samego skanera.** Rate limit, okna czasowe, sygnatury odporne na SSRF i ReDoS, szyfrowanie at rest (Fernet), RBAC. Narzędzie, które można wpuścić do sieci uczelni.

## Operating Context

- Główny ekran: **laptop albo monitor operatora** przy biurku, praca z bliska na gęstych danych (tabele hostów, triage, edycja, diff), obok terminala i innych narzędzi. Widok ścienny i projektor są drugorzędne. Demo dla jury i tak musi być czytelne z projektora.
- Rytm pracy: skany cykliczne według harmonogramu (okno czasowe i częstotliwość). Skan przekraczający okno zostaje zatrzymany i podjęty w kolejnym oknie. Operator wraca, żeby sprawdzić, co się zmieniło od ostatniego przebiegu.
- Integracje: DefectDojo (Generic Findings Import, findingi informacyjne lub evidence). Mentorzy zalecają lokalną instancję DefectDojo zamiast współdzielonego demo. Opcjonalnie OpenVAS/GVM jako głęboki skan w tle.
- Uruchomienie u jury: Docker. Na Linuksie `network_mode: host`, na Docker Desktop mapowanie portów.

## Capabilities and Constraints

Zaimplementowane (szczegóły i mapowanie wymóg→kod w `docs/architektura.md` §9): import CIDR/IP/domen i import wyników, limit `ASI_MAX_TARGETS`, adaptacyjne paczki portów, `rate_limit` per skan, postęp i czas trwania na żywo, 4 role, szyfrowanie at rest, własne sygnatury (nagłówek, ciasteczko, regex, ścieżka, hash favicony), fingerprinting i CMS, diff i flapping, harmonogram z oknem czasowym, eksport do DefectDojo, triage z nadpisaniami trwałymi między skanami (`finding_overrides`), Command Center.

Ograniczenia produktu:
- Sygnatury służą do **bezpiecznej detekcji**, nie do eksploatacji (ścieżki typu `/admin` bez prób logowania).
- Edycja wprowadzonych wartości musi być możliwa niezależnie od stanu skanu i musi przetrwać kolejne skany.
- Interfejs musi być czytelny dla każdej roli i mieć główny dashboard z najważniejszymi znaleziskami.
- **Język UI: przełącznik PL/EN** od początku. Identyfikatory techniczne zostają w oryginale.

Znane zaległości (według `CURSOR_HANDOFF.md` §3): ponawianie pojedynczego hosta w ramach jednego skanu, prawdziwe wznowienie po `paused_window` (dziś skan startuje od nowa), brak testów pytest, prezentacja odłożona na koniec.

## Brand Commitments

- Nazwa: **Attack Surface Intelligence (ASI)**. Logo ani znak graficzny nie istnieją.
- Głos: **zwięzły, operatorski**. Fakty i liczby, zero marketingu, styl narzędzi CLI. Przykład: „3 nowe usługi · 1 host zniknął · skan 42 min”.
- Motyw: **ciemny domyślnie, plus tryb jasny**.
- Wiążąca referencja wizualna od użytkownika: `.impeccable/references/visual-reference-datav.png`. To dashboard w stylu DataV: czarne tło, monochromatyczny wireframe i siatka, oszczędne akcenty pomarańczu i czerwieni, cienkie ramki i znaczniki w stylu HUD. Rozwinięcie w świat wizualny należy do etapu projektowego (DESIGN.md), nie do tego pliku.

## Evidence on Hand

- `scanme.nmap.org`: bezpieczny publiczny cel testowy, można go pokazywać bez ograniczeń.
- Realny skan własnej sieci `/20`: 4094 hosty, 556 ustaleń, score 100, około 97 minut. Liczby wolno cytować. Adresów i szczegółów hostów nie publikujemy w materiałach (założenie do potwierdzenia).
- **Lab AGH** (`lab/`, udostępniony 2026-11-21). Według organizatorów finalna ocena odbędzie się na podobnym szablonie, traktowanym jako inspiracja, a nie checklista. Cztery stacki `docker compose`, uruchamiane pojedynczo, wszystkie na `localhost`:
  - `modern`: WordPress, phpMyAdmin, Redis, Nginx Proxy Manager.
  - `modern-proxy`: Traefik, Toxiproxy (opóźnienia, timeouty).
  - `vulnerable`: FTP, WordPress 4.7, Adminer, DVWA.
  - `custom-network`: httpbin, PostgreSQL, RabbitMQ, Gitea, nginx na 8787.

  `quickstart.sh` demonstruje usługę, która znika i wraca (port 8787). Wniosek: na ocenie skala to **jeden host i kilkanaście usług**, a nie 10 000 IP, więc UI musi działać na obu krańcach. Wyniki referencyjne, przykładowe sygnatury i format importu/eksportu nadal nie zostały udostępnione.
- Dokumentacja: `docs/architektura.md`, `docs/screnariusz.md` (scenariusz demo), `docs/openvas.md`, szkic prezentacji `docs/prezentacja.html`.
- Brak: testimoniali, klientów, benchmarków porównawczych z SecureCodeBox. Tego nie zmyślamy.

## Product Principles

1. **Zmiana ponad stan.** Najważniejsza informacja to, co się zmieniło od ostatniego przebiegu i na ile jesteśmy tego pewni. Pełna lista otwartych portów jest na drugim planie.
2. **Sygnał z 10 000 wierszy.** Każdy widok zaczyna się od tego, co warto przeanalizować (priorytet analityczny), i skaluje się do dużych zakresów bez utraty czytelności.
3. **Ostrożność widoczna.** Tempo, okna czasowe, uprawnienia i szyfrowanie nie są ukryte. Operator i jury widzą, że skaner działa bezpiecznie.
4. **Ekspert przy biurku.** Projektujemy dla technika, który pracuje z bliska, z klawiatury, na gęstych danych. Nie upraszczamy kosztem precyzji.
5. **Specyfikacja jest granicą.** Funkcje wynikają z treści zadania AGH. Nic spoza niej nie dodajemy.

## Accessibility & Inclusion

- **WCAG 2.2 AA.**
- **Bezpieczne dla daltonistów:** stan (nowy, zniknął, zmieniony, flapping, ważność) nigdy nie jest kodowany samym kolorem. Zawsze towarzyszy mu kształt, ikona albo etykieta.
- **Pełna obsługa klawiaturą:** nawigacja po tabelach i triage bez myszy, skróty klawiszowe, widoczny focus.
- Oba motywy (ciemny i jasny) spełniają kontrasty AA.
