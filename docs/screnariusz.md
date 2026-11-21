# Scenariusz prezentacji: Attack Surface Intelligence (max 2 min)

Prezentacja na komputerze, na żywo, realny skan celu `scanme.nmap.org` w trybie lekkim (przyspieszonym).

`scanme.nmap.org` to oficjalny cel testowy projektu Nmap. Jego skanowanie jest dozwolone.

---

## 1. Przygotowanie (przed prezentacją)

1. Uruchom aplikację: `bash run.sh`, adres `http://127.0.0.1:8000`.
2. Przeglądarka na pełnym ekranie, powiększenie ok. 125%, jedna karta, bez zakładek i powiadomień.
3. Wykonaj **skan próbny** `scanme.nmap.org` tuż przed pokazem. Dzięki temu na żywo pokażesz sekcję „Zmiany od poprzedniego sprawdzenia". Bez wcześniejszego skanu ta sekcja jest pusta.
4. Sprawdź połączenie z internetem (subdomeny, Shodan, CISA KEV i NVD z niego korzystają). W Ustawieniach zobacz, które narzędzia są zainstalowane, ale **nie pokazuj widza okna z kluczami API**.
5. Ustawienia skanu dla przyspieszenia:
   - **nie** zaznaczaj „Tryb dokładny" (crawling, amass, testssl, whatweb `-a 3`),
   - **nie** zaznaczaj nuclei,
   - **nie** zaznaczaj „Sprawdzaj automatycznie".
6. Plan B: gotowy skan z historii (otwierany z ekranu startowego), gdyby sieć lub skan zawiodły.

---

## 2. Przebieg z tekstem (do wypowiedzenia)

### 0:00–0:15 Problem i idea

**Na ekranie:** ekran startowy, nagłówek „Sprawdź, czy strona Twojej instytucji jest bezpieczna".

**Co robisz:** pokazujesz nagłówek i formularz. Niczego jeszcze nie klikasz.

**Tekst:**
> „Każda instytucja ma stronę internetową, ale rzadko wie, co z niej widać z zewnątrz: jakie usługi, otwarte porty, subdomeny i przestarzałe oprogramowanie. To właśnie widzi atakujący. Ta aplikacja robi to samo, czyli mapuje powierzchnię ataku. Jest przeznaczona dla osoby nietechnicznej, więc wynik dostaje po polsku, w jednym zdaniu, razem z tym, co naprawić."

### 0:15–0:30 Start skanu

**Na ekranie:** formularz.

**Co robisz:**
1. Wpisujesz `scanme.nmap.org` w pole adresu.
2. Zaznaczasz pole oświadczenia o zgodzie właściciela.
3. Klikasz **Sprawdź stronę**.

**Tekst:**
> „Wpisuję adres. Aplikacja nie ruszy, dopóki nie potwierdzę, że strona należy do mnie albo mam zgodę właściciela, bo skanowanie cudzych systemów może być niezgodne z prawem. Używam scanme.nmap.org, czyli celu udostępnionego do testów przez twórców Nmapa. Tryb lekki, pasywny: bez crawlingu i bez agresywnych testów."

### 0:30–1:05 Skan w toku (najdłuższy fragment)

**Na ekranie:** widok postępu z etapami (odświeżanie co 2 s).

**Co robisz:** nie klikasz. Wskazujesz kursorem kolejne etapy w miarę ich pojawiania się.

**Tekst:**
> „Pod spodem działa łańcuch narzędzi znanych z Kali: subfinder szuka subdomen, dnsx rozwiązuje DNS, naabu i nmap skanują porty, httpx bada usługi WWW. Do tego dochodzą kontrole tylko do odczytu: ukryte pliki, takie jak `.git` czy `.env`, konfiguracja SPF i DMARC, wersje TLS oraz plik security.txt. Całość uzupełnia wywiad zewnętrzny: Shodan, lista CISA KEV z podatnościami wykorzystywanymi w atakach i baza NVD. Jeśli któregoś narzędzia brakuje, zastępuje je fallback w Pythonie, więc aplikacja działa na każdej maszynie."

**Uwaga:** jeśli skan trwa dłużej niż ok. 35 s, mów dalej o architekturze (powyższy tekst można rozciągnąć o zdanie o allowliście celów i walidacji wejścia: komendy działają bez powłoki, więc nie ma command injection). Jeśli po ok. 50 s nadal trwa, przełącz się na skan próbny z historii.

### 1:05–1:25 Wynik

**Na ekranie:** ocena 0–100, podsumowanie w jednym zdaniu, lista „Co zrobić najpierw".

**Co robisz:** przewijasz do listy uwag i rozwijasz jedną pozycję (np. otwarty port lub stara wersja usługi), żeby pokazać pole „Co zrobić".

**Tekst:**
> „Skan skończony. Dostajemy ocenę ryzyka od 0 do 100 i jedno zdanie podsumowania. Uwagi są ułożone od najważniejszej, a waga jest zawsze podana tekstem i kształtem, nie tylko kolorem. Przy każdej jest źródło ustalenia i zalecenie »Co zrobić«, które można przekazać informatykowi bez zmian. Na scanme zobaczymy otwarte porty i starsze oprogramowanie, i to jest celowe, bo ten host służy do testów."

### 1:25–1:45 Zmiany w czasie

**Na ekranie:** sekcja „Zmiany" oraz trend oceny.

**Co robisz:** przewijasz do zmian i pokazujesz wykres trendu. Opcjonalnie wskazujesz przycisk **Sprawdź ponownie**.

**Tekst:**
> „Najważniejsza jest zmiana w czasie. Aplikacja porównuje wynik z poprzednim skanem tego samego celu i pokazuje nowe zasoby, nowe pilne problemy oraz pogorszenie oceny. Skan można ustawić jako cykliczny, codziennie, co tydzień lub co miesiąc, a o istotnej zmianie dostaniemy powiadomienie przez webhook, np. na Slacku albo w Teams."

### 1:45–2:00 Dla informatyka i zakończenie

**Na ekranie:** rozwinięta sekcja „Dla informatyka".

**Co robisz:** rozwijasz sekcję, pokazujesz mapę powiązań i tabelę zasobów, wskazujesz eksport CSV/JSON i raport HTML.

**Tekst:**
> „Dla specjalisty jest warstwa techniczna: graf powiązań zasobów, tabela, dziennik narzędzi, eksport do CSV i JSON oraz raport HTML dla przełożonego. Podsumowując: jedno narzędzie, które pokazuje, co jest wystawione do internetu, co się zmieniło od ostatniego razu i co naprawić najpierw. Dziękuję."

---

## 3. Skrócona oś czasu

| Czas | Etap | Akcja |
|---|---|---|
| 0:00–0:15 | Problem | Ekran startowy |
| 0:15–0:30 | Start | Adres, zgoda, „Sprawdź stronę" |
| 0:30–1:05 | Skan | Postęp, narzędzia |
| 1:05–1:25 | Wynik | Ocena, uwagi, „Co zrobić" |
| 1:25–1:45 | Zmiany | Diff, trend, cykliczność |
| 1:45–2:00 | Technika | „Dla informatyka", eksport |

---

## 4. Ryzyka i plan awaryjny

| Problem | Rozwiązanie |
|---|---|
| Skan trwa dłużej niż 50 s | Otwórz skan próbny z historii, powiedz, że to ten sam wynik sprzed chwili |
| Brak internetu | Jak wyżej. Wywiad zewnętrzny i subdomeny pójdą na fallbacki, wynik będzie uboższy |
| Brak sekcji „Zmiany" | Nie wykonano skanu próbnego. Pomiń ten fragment i rozwiń wątek cykliczności |
| Nie ładuje się mapa powiązań | Biblioteka vis-network pochodzi z CDN. Pokaż tabelę zasobów (fallback) |

## 5. Czego nie robić na pokazie

- Nie włączaj trybu dokładnego ani nuclei. Skan nie zmieści się w 2 minutach i generuje dużo ruchu.
- Nie skanuj niczego poza `scanme.nmap.org` (zgoda właściciela).
- Nie pokazuj okna Ustawień z kluczami API.
