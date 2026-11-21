export async function api(path, opts) {
  let r
  try { r = await fetch(path, opts) } catch { throw new Error('Brak połączenia z programem. Sprawdź, czy jest uruchomiony, i spróbuj ponownie.') }
  const j = await r.json().catch(() => ({}))
  if (!r.ok) throw new Error(j.detail || r.statusText)
  return j
}

export const postScan = (body) =>
  api('/api/scans', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })

export const SEVS = ['critical', 'high', 'medium', 'low', 'info']
export const PL = { critical: 'Krytyczne', high: 'Wysokie', medium: 'Średnie', low: 'Niskie', info: 'Informacja' }
export const WHEN = {
  critical: 'Napraw natychmiast',
  high: 'Napraw w tym tygodniu',
  medium: 'Zaplanuj naprawę',
  low: 'Popraw przy okazji',
  info: 'Do wiadomości',
}
export const KIND_PL = { domain: 'adres główny', subdomain: 'adres podrzędny', ip: 'adres serwera', port: 'otwarta usługa', web: 'strona WWW' }
export const KIND_COLOR = { domain: '#0b4f9e', subdomain: '#13788c', ip: '#6d4aad', port: '#9a6a00', web: '#b3380a' }

export const isRunning = (s) => s === 'queued' || s === 'running'
export const scoreSev = (n) => (n >= 60 ? 'critical' : n >= 30 ? 'medium' : 'low')

/** Ocena ogólna dla osoby nietechnicznej. */
export function verdict(score, counts) {
  const urgent = (counts?.critical || 0) + (counts?.high || 0)
  if (score >= 60 || (counts?.critical || 0) > 0) {
    return { tone: 'bad', title: 'Wymaga pilnej uwagi', text: 'Znaleziono poważne problemy. Przekaż raport informatykowi jeszcze dziś.' }
  }
  if (score >= 30 || urgent > 0) {
    return { tone: 'warn', title: 'Wymaga poprawek', text: 'Znaleziono problemy, które warto naprawić w najbliższym czasie.' }
  }
  return { tone: 'good', title: 'Nie znaleziono poważnych problemów', text: 'Strona wygląda dobrze pod kątem tego, co sprawdza to narzędzie. To nie zastępuje pełnego audytu bezpieczeństwa.' }
}

export function plural(n, one, few, many) {
  if (n === 1) return one
  const m10 = n % 10, m100 = n % 100
  return m10 >= 2 && m10 <= 4 && !(m100 >= 12 && m100 <= 14) ? few : many
}

export function fmtTime(t) {
  if (!t) return ''
  return new Date(t * 1000).toLocaleString('pl-PL', { day: 'numeric', month: 'long', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}
export function fmtShort(t) {
  if (!t) return ''
  return new Date(t * 1000).toLocaleString('pl-PL', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}
export function assetLabel(a) {
  return a.kind === 'web' ? a.value.replace(/^https?:\/\//, '') : a.value
}
export function assetInfo(a) {
  const d = a.data || {}
  if (a.kind === 'web') return [d.status, d.title, d.server, (d.tech || []).join(', ')].filter(Boolean).join('  ')
  if (a.kind === 'port') return [d.service, d.version].filter(Boolean).join('  ')
  return ''
}

/* ---- etapy sprawdzania, po ludzku ---- */
export const STEPS = [
  { id: 'enum', match: /enumeracja/i, label: 'Szukam adresów należących do instytucji' },
  { id: 'dns', match: /dns/i, label: 'Sprawdzam, dokąd prowadzą te adresy' },
  { id: 'ports', match: /port/i, label: 'Sprawdzam, jakie usługi są otwarte z internetu' },
  { id: 'http', match: /http/i, label: 'Sprawdzam zabezpieczenia stron internetowych' },
  { id: 'extra', match: /dodatkowe/i, label: 'Sprawdzam ukryte pliki, pocztę e-mail i szyfrowanie' },
  { id: 'urls', match: /adres[óo]w url/i, label: 'Przeglądam adresy i technologie strony' },
  { id: 'intel', match: /wywiad/i, label: 'Sprawdzam znane podatności i wycieki w zewnętrznych bazach' },
  { id: 'vuln', match: /nuclei|podatno/i, label: 'Szukam znanych luk w oprogramowaniu', optional: true },
]
export function stepIndex(stage) {
  if (!stage) return -1
  return STEPS.findIndex((s) => s.match.test(stage))
}

/* ---- tłumaczenie ustaleń na zwykły język ---- */
const EXPLAIN = [
  [/aktywnie wykorzystywana/i, 'Dla oprogramowania na tym serwerze znana jest luka, którą przestępcy już wykorzystują w prawdziwych atakach (według rządowej listy CISA). To najpilniejszy rodzaj problemu: trzeba zaktualizować oprogramowanie od razu.'],
  [/podatno[śs][ćc]|CVE-/i, 'Dla wykrytego oprogramowania opublikowano informację o luce bezpieczeństwa. Aktualizacja do nowszej wersji ją usuwa.'],
  [/wyciekach/i, 'Adresy e-mail z Waszej domeny znalazły się w danych skradzionych z innych serwisów. Hasła z tych wycieków mogą być użyte do włamania na konta służbowe.'],
  [/AXFR/i, 'Serwer nazw pozwala każdemu pobrać pełną listę adresów instytucji, także tych, które nie powinny być znane z zewnątrz.'],
  [/protoko[łl]|heartbleed|ccs injection|robot|audyt tls/i, 'Szyfrowanie połączenia ze stroną ma słabość, która w pewnych warunkach pozwala podsłuchać lub odszyfrować dane odwiedzających.'],
  [/censys widzi/i, 'Zewnętrzna wyszukiwarka urządzeń widzi otwartą usługę, której nasze sprawdzenie nie potwierdziło. Może być dostępna tylko z niektórych miejsc w sieci.'],
  [/zapor[ęe] aplikacyjn|waf/i, 'Zapora aplikacyjna (WAF) filtruje typowe ataki na stronę. To informacja pomocnicza, nie błąd.'],
  [/x-powered-by/i, 'Strona ujawnia, na jakiej technologii działa. To ułatwia atakującemu wybór metody ataku.'],
  [/telnet/i, 'Na serwerze działa przestarzały sposób zdalnego logowania, który wysyła hasła bez szyfrowania. Każdy, kto podsłucha połączenie, pozna hasło.'],
  [/ftp/i, 'Serwer udostępnia pliki starą metodą bez szyfrowania. Hasła i pliki mogą zostać przechwycone.'],
  [/smb|netbios|ms-rpc|rpcbind/i, 'Usługa przeznaczona do pracy wewnątrz sieci urzędu jest widoczna z internetu. Takie usługi są częstym celem ataków, w tym ransomware.'],
  [/rdp|vnc/i, 'Zdalny pulpit jest dostępny z internetu. Przestępcy aktywnie go wyszukują i próbują zgadnąć hasło.'],
  [/baz[ay]|redis|mongo|elasticsearch/i, 'Baza danych jest dostępna z internetu. Osoba niepowołana może próbować dostać się do przechowywanych w niej danych.'],
  [/pptp/i, 'Używany jest przestarzały sposób zdalnego łączenia się z siecią, który można stosunkowo łatwo złamać.'],
  [/nieszyfrowan/i, 'Strona otwiera się także bez szyfrowania (adres zaczynający się od http://). To, co wpisują na niej użytkownicy, może zostać podejrzane.'],
  [/certyfikat.*wygas[łl]/i, 'Certyfikat, który potwierdza autentyczność strony, stracił ważność. Przeglądarki pokazują obywatelom ostrzeżenie o niebezpiecznej stronie.'],
  [/certyfikat.*wkr[óo]tce/i, 'Certyfikat potwierdzający autentyczność strony niedługo straci ważność. Po tym terminie przeglądarki będą ostrzegać odwiedzających.'],
  [/certyfikat/i, 'Certyfikat potwierdzający autentyczność strony jest nieprawidłowy. Przeglądarki mogą ostrzegać odwiedzających.'],
  [/hsts/i, 'Strona nie wymusza w przeglądarce bezpiecznego (szyfrowanego) połączenia. To drobne zabezpieczenie, które łatwo dodać.'],
  [/content-security-policy|x-content-type|x-frame|clickjack/i, 'Strona nie włącza dodatkowych zabezpieczeń, które przeglądarka mogłaby zastosować. To drobna słabość, ale poprawa jest szybka.'],
  [/wersji oprogramowania|server/i, 'Serwer zdradza dokładną wersję oprogramowania. Ułatwia to atakującemu dobranie metody ataku.'],
  [/\.env|\.git|backup|dump\.sql|wp-config|\.ds_store/i, 'Na stronie leży plik, którego nikt z zewnątrz nie powinien widzieć (kopia zapasowa, konfiguracja lub hasła). Przestępcy szukają takich plików automatycznie.'],
  [/phpinfo|server-status|actuator/i, 'Strona ujawnia wewnętrzne informacje o serwerze, które ułatwiają przygotowanie ataku.'],
  [/spf|dmarc/i, 'Domena nie jest chroniona przed podszywaniem się pod pocztę instytucji. Ktoś obcy może wysłać e-mail wyglądający jak od was, np. z prośbą o przelew.'],
  [/tls 1|wersje tls/i, 'Serwer dopuszcza przestarzałe szyfrowanie, które da się złamać. Nowoczesne przeglądarki go nie potrzebują.'],
  [/security\.txt/i, 'Brakuje strony z informacją, jak zgłosić odkrytą lukę. Badacze bezpieczeństwa nie wiedzą, do kogo napisać.'],
  [/panel administracyjn|logowania/i, 'Panel logowania lub administracji jest dostępny dla każdego w internecie. Powinien być widoczny tylko dla uprawnionych osób.'],
]
const NICE_TITLE = [
  [/telnet/i, 'Przestarzałe zdalne logowanie (Telnet) jest dostępne z internetu'],
  [/^ftp/i, 'Niezabezpieczony serwer plików (FTP) jest dostępny z internetu'],
  [/rdp/i, 'Zdalny pulpit (RDP) jest dostępny z internetu'],
  [/vnc/i, 'Zdalny pulpit (VNC) jest dostępny z internetu'],
  [/hsts/i, 'Strona nie wymusza bezpiecznego połączenia (brak HSTS)'],
  [/brak rekordu spf/i, 'Poczta instytucji nie jest chroniona przed podszywaniem się (brak SPF)'],
  [/brak rekordu dmarc/i, 'Poczta instytucji nie jest chroniona przed podszywaniem się (brak DMARC)'],
]
export function explain(f) {
  const hit = EXPLAIN.find(([re]) => re.test(f.title))
  return hit ? hit[1] : 'Narzędzie wykryło problem. Przekaż go informatykowi razem z raportem.'
}
export function niceTitle(f) {
  const hit = NICE_TITLE.find(([re]) => re.test(f.title))
  return hit ? hit[1] : f.title
}
