# Scenariusz prezentacji: Attack Surface Intelligence

Scenariusz modułowy - bloki po 15-25 s, które składa się w dowolną długość demo
(na sztywno nieznaną na etapie pisania tego dokumentu). Każdy blok ma zaznaczony
czas, stan ekranu i tekst do powiedzenia, więc da się przyciąć do 2 minut (same
bloki oznaczone **[rdzeń]**) albo rozciągnąć do 5+ minut (wszystkie bloki).

**Ważne:** ten dokument opisuje wyłącznie funkcje, które faktycznie działają w
kodzie na dzień pisania (branch `babunia`). Poprzednia wersja tego scenariusza
wspominała integrację z Shodan/CISA KEV/NVD oraz harmonogram cyklicznych skanów
z powiadomieniami webhook - **żadne z tych dwóch nie istnieje w kodzie**, więc
zostały usunięte stąd, żeby nikt nie obiecał jury czegoś, czego nie da się pokazać.

---

## 0. Kontekst techniczny demo

- Aplikacja: `bash run.sh` (domyślnie `http://127.0.0.1:8000`; w tej sesji deweloperskiej
  chodzi też na `:8099` - sprawdź port przed wyjściem na scenę).
- Przy pierwszym starcie na świeżej bazie powstaje użytkownik `admin` z losowym hasłem
  wypisanym **raz** w logu terminala przy starcie (`[asi] utworzono pierwszego
  użytkownika: admin / <hasło>`) - zapisz je sobie przed prezentacją, nie da się go
  odzyskać inaczej.
- Cel testowy do demo na żywo: `scanme.nmap.org` (oficjalny cel testowy Nmap, zgoda
  na skanowanie jest domniemana przez jego twórców). **Uwaga:** to współdzielony
  publiczny host - bywa niestabilny (sama tego doświadczyłam podczas developmentu:
  port 80 bywa "filtered" bez związku z naszym kodem). Miej gotowy plan B (§4).
- Jury może testować na własnym środowisku laboratoryjnym dostarczonym przez AGH
  (p. 7 specyfikacji) - aplikacja przyjmuje dowolny host/CIDR/domenę z formularza,
  nic nie trzeba przebudowywać pod ich adresację.

---

## 1. Przygotowanie (przed wyjściem na scenę)

1. `bash run.sh`, sprawdź adres w terminalu.
2. Zaloguj się jako `admin`. Przeglądarka pełny ekran, ~125% powiększenia.
3. Wykonaj **skan próbny** `scanme.nmap.org` (bez nuclei/OpenVAS) kilka minut wcześniej,
   żeby sekcja "Zmiany względem poprzedniego skanu" miała z czym porównywać na żywo.
4. Opcjonalnie przygotuj mały plik `demo-targets.csv` z 3-4 adresami (do bloku D) -
   nie trzeba realnej dużej sieci na scenie, kilka wierszy wystarczy, żeby pokazać
   mechanizm importu.
5. Jeśli pokazujesz DefectDojo: miej otwartą drugą kartę z `https://demo.defectdojo.org`
   zalogowaną, żeby po kliknięciu "Eksportuj" przełączyć się i pokazać wynik.
6. Utwórz wcześniej drugiego użytkownika z rolą `read`, żeby mieć gotowe dane logowania
   do bloku RBAC (nie zakładaj konta na żywo, jeśli nie musisz).

---

## 2. Bloki (składaj w dowolnej kolejności/długości)

### Blok A - Problem i idea **[rdzeń, ~15 s]**
**Ekran:** ekran logowania.
**Tekst:** "Duże organizacje mają rozległą infrastrukturę, której często same do końca
nie znają - adresy, które czasem odpowiadają, czasem nie, usługi wystawione przez
przypadek. Atak zaczyna się od rozpoznania. To narzędzie robi to samo, ale dla
obrońcy: discovery scan dużej sieci, priorytetyzacja i śledzenie zmian w czasie."

### Blok B - Logowanie i role **[rdzeń, ~15 s]**
**Ekran:** logowanie jako `admin`, potem (opcjonalnie) jako user z rolą `read`.
**Tekst:** "Dostęp jest po rolach: administrator, ktoś kto może dodawać/usuwać/
modyfikować, ktoś kto może tylko edytować i czytać, i czysty odczyt. [przełącz na
usera `read`] Ta sama aplikacja, ale formularz nowego skanu po prostu znika -
rola to wymusza po stronie serwera, nie tylko ukrywa przycisk w przeglądarce."

### Blok C - Start skanu, wiele celów naraz **[rdzeń, ~20 s]**
**Ekran:** formularz (jako `admin`).
**Co robisz:** w polu celów wklej `scanme.nmap.org`, zaznacz zgodę, kliknij "Uruchom skan".
**Tekst:** "Cel może być pojedynczą domeną, adresem IP, albo całym zakresem CIDR -
jeden na linię albo po przecinku. Tu jedna domena dla szybkości demo, ale mechanizm
jest ten sam dla tysięcy adresów na raz - obsługujemy zadaną w specyfikacji skalę
ponad 10 000 adresów. Aplikacja nie ruszy bez potwierdzenia zgody właściciela."

### Blok D - Import listy/CIDR z pliku **[rozszerzenie, ~20 s]**
**Ekran:** sekcja "Import pliku (CSV/JSON)".
**Co robisz:** wgrywasz `demo-targets.csv`, klikasz "Importuj i skanuj".
**Tekst:** "Drugi sposób wprowadzenia celów: plik CSV albo JSON, dokładnie ten sam
format, który aplikacja sama produkuje przy eksporcie - więc wynik jednego skanu
można bez przeróbek wrzucić z powrotem jako wsad do kolejnego albo do innej instancji."

### Blok E - Skan w toku, skala **[rdzeń, ~20 s]**
**Ekran:** widok postępu, pasek `hosts_done/hosts_total`.
**Tekst:** "Skan portów idzie paczkami adresów, które same się dostrajają do
zmierzonej przepustowości - stąd widoczny, aktualizowany na żywo postęp i czas
trwania, a nie czarna skrzynka. Limit pakietów na sekundę jest konfigurowalny,
żeby nie zalać skanowanej sieci."

**Uwaga:** jeśli skan trwa dłużej niż ok. 40 s, mów dalej o architekturze (allowlista
celów, komendy bez powłoki - brak command injection) albo przejdź do Bloku B/D,
wracając do wyniku później.

### Blok F - Wynik i ustalenia **[rdzeń, ~20 s]**
**Ekran:** wynik ryzyka 0-100, lista ustaleń.
**Co robisz:** rozwijasz jedno ustalenie, pokazujesz pole "Co zrobić" i kolumnę źródła.
**Tekst:** "Ocena ryzyka 0-100, ustalenia posortowane od najważniejszych, każde z
zaleceniem naprawy i źródłem - czy to wbudowana reguła, nuclei, OpenVAS, czy
własna sygnatura. Scanme ma otwarte porty i starą wersję oprogramowania celowo -
to host testowy."

### Blok G - Własne sygnatury **[rozszerzenie, ~20 s]**
**Ekran:** sekcja "Własne sygnatury" w panelu bocznym.
**Co robisz:** pokazujesz listę, dodajesz jedną (np. `header_present` / `X-Powered-By`).
**Tekst:** "Jury może dostarczyć własny zestaw sygnatur - obsługujemy nagłówki,
nazwy ciasteczek, wzorce w HTML, sprawdzenie istnienia ścieżki typu /admin bez
żadnej próby logowania, i hash favicony. Wyłącznie bezpieczna detekcja obecności
cechy, nigdy eksploatacja."

### Blok H - Zmiany w czasie **[rdzeń, ~20 s]**
**Ekran:** sekcja "Zmiany względem skanu #N" (wymaga wcześniejszego skanu próbnego z §1.3).
**Co robisz:** klikasz "Skanuj ponownie", po zakończeniu przewijasz do diffu.
**Tekst:** "Każdy kolejny skan tego samego celu jest automatycznie porównywany z
poprzednim - nowe zasoby, zniknięte zasoby, nowe i naprawione ustalenia. To jest
sedno specyfikacji: nie pojedynczy skan, tylko to, co się zmieniło."

### Blok I - Eksport i DefectDojo **[rozszerzenie, ~20 s]**
**Ekran:** przyciski eksportu pod wynikiem skanu.
**Co robisz:** klikasz "Eksportuj do DefectDojo", przełączasz kartę, odświeżasz
widok findingów w DefectDojo.
**Tekst:** "Eksport do JSON i CSV do dalszej analizy, raport HTML dla przełożonego,
i bezpośrednia integracja z DefectDojo - findingi lądują tam jako gotowy test w
ramach produktu i engagementu, bez ręcznego przepisywania."

### Blok J - Bezpieczeństwo działania **[rozszerzenie, ~15 s]**
**Tekst (bez konkretnego ekranu, można mówić nad dowolnym widokiem):** "Same dane
są istotne, więc szczegóły ustaleń i logi skanów są szyfrowane w spoczynku.
Komendy do narzędzi skanujących idą bez powłoki systemowej, więc nie ma
command injection, a moduł własnych sygnatur ma wbudowaną ochronę przed SSRF i
przed złośliwymi wzorcami regex, które mogłyby zawiesić skan."

### Blok K - Zakończenie **[rdzeń, ~10 s]**
**Tekst:** "Jedno narzędzie: discovery na dużą skalę, priorytetyzacja, co zmieniło
się od ostatniego razu, role dostępu i integracja z DefectDojo. Dziękuję."

---

## 3. Sugerowane złożenia

| Budżet czasu | Bloki |
|---|---|
| ~2 min (rdzeń) | A, C, E, F, H, K |
| ~3 min | A, B, C, E, F, H, K |
| ~5 min (pełne) | A, B, C, D, E, F, G, H, I, J, K |

---

## 4. Ryzyka i plan awaryjny

| Problem | Rozwiązanie |
|---|---|
| `scanme.nmap.org` nie odpowiada na dany port (bywa) | To normalne dla współdzielonego publicznego hosta - powiedz to wprost, to dobry przykład "niestabilnego hosta" z własnej specyfikacji AGH. Przełącz się na skan próbny z historii (Plan B). |
| Skan trwa dłużej niż ok. 40-50 s | Mów dalej o architekturze (Blok J) albo przeskocz do bloku z gotowym wcześniejszym skanem. |
| Brak internetu | Enumeracja subdomen (crt.sh) i część fingerprintingu pójdą na fallback, wynik będzie uboższy, ale aplikacja nie padnie. |
| Brak sekcji "Zmiany" | Nie wykonano skanu próbnego z §1.3 - pomiń Blok H albo zrób "Skanuj ponownie" na żywo i opowiedz o mechanizmie bez pokazywania konkretnego diffu. |
| Nie ładuje się mapa powiązań | Biblioteka vis-network z CDN, wymaga internetu - pokaż tabelę zasobów (zawsze działa, bez CDN). |
| DefectDojo demo niedostępne/wolne | Pomiń Blok I albo pokaż sam request/response z wcześniej przygotowanego nagrania ekranu. |

## 5. Czego nie robić na pokazie

- Nie skanuj niczego poza `scanme.nmap.org` i własnym przygotowanym plikiem CSV/JSON
  bez realnych, obcych adresów (zgoda właściciela!).
- Nie włączaj nuclei/OpenVAS w krótkim demo - za wolne, generują dużo ruchu.
- Nie pokazuj widzowi wygenerowanego hasła admina ani kluczy API (DefectDojo) na ekranie.
- Nie obiecuj funkcji, których nie ma w kodzie (harmonogram cyklicznych skanów,
  Shodan/CISA KEV/NVD) - jeśli ktoś z jury zapyta, powiedz wprost, że to na roadmapie.
