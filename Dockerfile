# Attack Surface Intelligence. Build: docker compose build
# Wszystkie narzędzia skanujące wbudowane w obraz - nie wymaga WSL/Kali/ręcznej instalacji.
#   --build-arg WITH_TOOLS=0  -> szybki obraz bez narzędzi skanujących (aplikacja użyje fallbacków w Pythonie;
#                                tak buduje CI)
ARG WITH_TOOLS=1

# Kompilacja narzędzi (potrzebują Go), potem lekki finalny obraz z Pythonem + nmap + skompilowane binarki.
FROM golang:1.23-bookworm AS tools
ARG WITH_TOOLS
# GOTOOLCHAIN=auto: narzędzia ProjectDiscovery regularnie podnoszą wymagany Go szybciej niż warto gonić tagiem obrazu
# bazowego; auto każe dociągnąć właściwy toolchain per moduł.
ENV GOTOOLCHAIN=auto GOBIN=/out CGO_ENABLED=1
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev && rm -rf /var/lib/apt/lists/*
# błąd jednego narzędzia nie blokuje obrazu (aplikacja ma fallbacki); smoke test sprawdza, że sześć podstawowych jest
RUN mkdir -p /out && if [ "$WITH_TOOLS" = "1" ]; then for p in \
      github.com/projectdiscovery/subfinder/v2/cmd/subfinder \
      github.com/projectdiscovery/dnsx/cmd/dnsx \
      github.com/projectdiscovery/httpx/cmd/httpx \
      github.com/projectdiscovery/naabu/v2/cmd/naabu \
      github.com/projectdiscovery/nuclei/v3/cmd/nuclei \
      github.com/projectdiscovery/katana/cmd/katana \
      github.com/lc/gau/v2/cmd/gau \
      github.com/tomnomnom/waybackurls \
      github.com/tomnomnom/assetfinder \
      github.com/owasp-amass/amass/v4/... ; do \
      go install "$p@latest" || echo "POMINIĘTO $p"; done; fi

# Panel (Vite + React) budowany ze źródeł w osobnym etapie: w finalnym obrazie zostaje tylko statyczny dist/, bez
# node_modules - obraz nigdy nie zawiera nieaktualnego UI. Czcionki są w paczce (@fontsource), więc UI działa offline.
FROM node:22-bookworm-slim AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim-bookworm
ARG WITH_TOOLS
ARG ASI_VERSION=dev
LABEL org.opencontainers.image.title="attack-surface-intelligence" org.opencontainers.image.version="$ASI_VERSION"

RUN apt-get update && apt-get install -y --no-install-recommends nmap libpcap0.8 libcap2-bin ca-certificates \
    && if [ "$WITH_TOOLS" = "1" ]; then \
         apt-get install -y --no-install-recommends git whatweb \
         && git clone --depth 1 https://github.com/testssl/testssl.sh /opt/testssl.sh \
         && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh \
         && apt-get purge -y git && apt-get autoremove -y && rm -rf /opt/testssl.sh/.git; fi \
    && rm -rf /var/lib/apt/lists/*

# Osobny katalog na początku PATH, NIE /usr/local/bin: pip (fastapi -> httpx) instaluje tam pythonowy skrypt "httpx",
# który nadpisywał binarkę ProjectDiscovery i etap HTTP po cichu przechodził na fallback.
COPY --from=tools /out/ /opt/pd/bin/
ENV PATH=/opt/pd/bin:$PATH
# Pozwala na szybszy SYN scan (naabu -s s) zamiast domyślnego, wolnego connect scan - w praktyce i tak nadpisane przez
# cap_add w docker-compose.yml (kontener chodzi jako root), ale zostaje jako zabezpieczenie na wypadek uruchomienia
# obrazu inaczej. Samo NET_RAW wystarcza do craftowania pakietów SYN - NET_ADMIN nie jest do tego potrzebne.
RUN if [ "$WITH_TOOLS" = "1" ]; then setcap cap_net_raw=eip /opt/pd/bin/naabu || true; fi

WORKDIR /app
COPY requirements.txt requirements-tools.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && if [ "$WITH_TOOLS" = "1" ]; then pip install --no-cache-dir -r requirements-tools.txt; fi
RUN if [ "$WITH_TOOLS" = "1" ]; then nuclei -update-templates || true; fi

COPY asi ./asi
COPY static ./static
COPY --from=web /web/dist ./frontend/dist

ENV ASI_HOST=0.0.0.0 \
    ASI_PORT=8000 \
    ASI_DB=/data/asi.db \
    ASI_SECRET_KEY_FILE=/data/secret.key \
    ASI_VERSION=$ASI_VERSION \
    PYTHONUNBUFFERED=1

VOLUME ["/data"]
EXPOSE 8000
# Bez curla w obrazie - sprawdzenie przez Pythona, który i tak jest. /api/health nie wymaga sesji i sprawdza, czy baza
# ma oczekiwaną wersję schematu (przydatne po wdrożeniu i po wycofaniu).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import json,os,urllib.request as u; assert json.load(u.urlopen('http://127.0.0.1:%s/api/health' % os.environ.get('ASI_PORT','8000'), timeout=4))['status']=='ok'" || exit 1
# Przez sh -c, żeby ASI_HOST/ASI_PORT z environment: w compose faktycznie się podstawiały. Domyślnie 0.0.0.0 jest
# świadome: to narzędzie demo ma być dostępne z innych maszyn w sieci (jury na swoim laptopie) - kto chce ograniczyć do
# localhost, ustawia ASI_HOST=127.0.0.1. "exec" podmienia powłokę na uvicorn (PID 1), żeby docker stop (SIGTERM)
# zamykał serwer od razu, zamiast czekać 10 s na SIGKILL.
CMD ["sh", "-c", "exec uvicorn asi.main:app --host ${ASI_HOST} --port ${ASI_PORT}"]
