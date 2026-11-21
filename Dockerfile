# Wszystkie narzędzia skanujące wbudowane w obraz - nie wymaga WSL/Kali/ręcznej instalacji
# go install na hoście. Dwuetapowo: kompilacja narzędzi ProjectDiscovery (potrzebują Go),
# potem lekki finalny obraz z Pythonem + nmap + skompilowane binarki.

FROM golang:1.23-bookworm AS tools
# GOTOOLCHAIN=auto (domyślne od Go 1.21, ale niektóre obrazy je nadpisują na "local") -
# narzędzia ProjectDiscovery regularnie podnoszą wymagany Go szybciej niż warto gonić tagiem
# obrazu bazowego; auto każe go samemu dociągnąć właściwy toolchain per moduł.
ENV GOTOOLCHAIN=auto
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
 && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
 && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Panel (Vite + React) budowany w osobnym etapie: w finalnym obrazie zostaje tylko statyczny
# dist/, bez node_modules. Czcionki są w paczce (@fontsource), więc UI działa offline w labie.
FROM node:22-bookworm-slim AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap libpcap0.8 libcap2-bin ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Oficjalny obraz golang ustawia GOPATH=/go (nie ~/go jak w naszych środowiskach WSL) -
# stąd go install ląduje w /go/bin, nie /root/go/bin.
# Osobny katalog na początku PATH, NIE /usr/local/bin: pip (fastapi -> httpx) instaluje tam
# pythonowy skrypt "httpx", który nadpisywał binarkę ProjectDiscovery i etap HTTP po cichu
# przechodził na fallback.
COPY --from=tools /go/bin/* /opt/pd/bin/
ENV PATH=/opt/pd/bin:$PATH
# Pozwala na szybszy SYN scan (naabu -s s) zamiast domyślnego, wolnego connect scan - w
# praktyce i tak nadpisane przez cap_add w docker-compose.yml (kontener i tak chodzi jako
# root), ale zostaje jako zabezpieczenie na wypadek uruchomienia obrazu inaczej (np. z
# dodanym tylko NET_RAW dla non-root usera). Samo NET_RAW wystarcza do craftowania pakietów
# SYN - NET_ADMIN (kontrola interfejsów sieciowych) nie jest do tego potrzebne.
RUN setcap cap_net_raw=eip /opt/pd/bin/naabu || true

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY asi ./asi
COPY static ./static
COPY --from=web /web/dist ./frontend/dist

ENV ASI_HOST=0.0.0.0 \
    ASI_PORT=8000 \
    ASI_DB=/data/asi.db \
    ASI_SECRET_KEY_FILE=/data/secret.key \
    PYTHONUNBUFFERED=1

VOLUME ["/data"]
EXPOSE 8000
# Bez curla w obrazie - sprawdzenie przez Pythona, który i tak jest. "/" nie wymaga sesji.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/' % os.environ.get('ASI_PORT','8000'), timeout=4)" || exit 1
# Przez sh -c, żeby ASI_HOST/ASI_PORT z environment: w compose faktycznie
# się podstawiały - wcześniej CMD miał te wartości wbite na trwałe i zmienne nic nie zmieniały.
# Domyślnie 0.0.0.0 jest świadome: to narzędzie demo ma być dostępne z innych maszyn w sieci
# (jury na swoim laptopie) - kto chce ograniczyć do localhost, ustawia ASI_HOST=127.0.0.1.
# "exec" podmienia powłokę na uvicorn (PID 1), żeby docker stop (SIGTERM) zamykał serwer od razu,
# zamiast czekać 10 s na SIGKILL.
CMD ["sh", "-c", "exec uvicorn asi.main:app --host ${ASI_HOST} --port ${ASI_PORT}"]
