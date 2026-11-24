# Roadmapa

Estymacje to zakresy (optymistyczna / najbardziej prawdopodobna / pesymistyczna) w dniach roboczych jednej osoby,
z wartością oczekiwaną PERT `(O + 4M + P) / 6`. Po zakończeniu pozycji dopisz faktyczny czas w kolumnie „Wynik”,
żeby kalibrować kolejne estymacje.

| # | Zadanie | Dlaczego | O / M / P | PERT | Pewność | Wynik |
|---|---|---|---|---|---|---|
| 1 | Uwierzytelnianie API (token lub OIDC za reverse proxy) | API uruchamia skany i trzyma klucze; dziś chroni je tylko nasłuch na localhost | 1 / 2 / 4 | 2,2 | średnia | zrobione |
| 2 | Szyfrowanie kluczy API w bazie (klucz z `ASI_SECRET_KEY`) | Klucze leżą w SQLite jako tekst | 0,5 / 1 / 2 | 1,1 | wysoka | zrobione |
| 3 | Anulowanie trwającego skanu z UI | Dziś długi skan blokuje kolejkę do końca | 1 / 2 / 3 | 2,0 | średnia | zrobione |
| 4 | Retencja: automatyczne usuwanie starych skanów | Baza rośnie bez ograniczeń przy monitoringu | 0,5 / 1 / 1,5 | 1,0 | wysoka | |
| 5 | Kilka skanów równolegle (pula zamiast `Semaphore(1)`) | Monitoring wielu celów | 2 / 3 / 6 | 3,3 | niska: limity zewnętrznych API | zrobione |
| 6 | Testy kontraktowe parserów na nagranych wynikach narzędzi (nmap, httpx, nuclei) | Zmiana formatu wyjścia narzędzia psuje etap po cichu | 1 / 1,5 / 3 | 1,7 | wysoka | |

Pozycje o niskiej pewności zaczynamy od ograniczonego czasowo spike'a (maks. 1 dzień), a potem estymujemy ponownie.
