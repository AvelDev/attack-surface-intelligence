# Attack Surface Intelligence. Build: docker compose build
#   --build-arg WITH_TOOLS=0  -> szybki obraz bez narzędzi skanujących (aplikacja użyje fallbacków w Pythonie; tak buduje CI)
ARG WITH_TOOLS=1

FROM golang:1.23-bookworm AS gotools
ARG WITH_TOOLS
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev && rm -rf /var/lib/apt/lists/*
ENV GOBIN=/out CGO_ENABLED=1
# błąd jednego narzędzia nie blokuje obrazu (aplikacja ma fallbacki)
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

# frontend budowany ze źródeł - obraz nigdy nie zawiera nieaktualnego UI
FROM node:26-bookworm-slim AS frontend
WORKDIR /src
COPY asi/domain.json asi/domain.json
COPY frontend/package.json frontend/package-lock.json frontend/
RUN cd frontend && npm ci --no-audit --no-fund
COPY frontend frontend
RUN cd frontend && npm run build

FROM python:3.12-slim-bookworm
ARG WITH_TOOLS
ARG ASI_VERSION=dev
LABEL org.opencontainers.image.title="attack-surface-intelligence" org.opencontainers.image.version="$ASI_VERSION"
RUN if [ "$WITH_TOOLS" = "1" ]; then \
      apt-get update && apt-get install -y --no-install-recommends nmap libpcap0.8 git ca-certificates whatweb \
      && git clone --depth 1 https://github.com/testssl/testssl.sh /opt/testssl.sh \
      && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh \
      && apt-get purge -y git && apt-get autoremove -y && rm -rf /var/lib/apt/lists/* /opt/testssl.sh/.git; fi
COPY --from=gotools /out/ /usr/local/bin/
WORKDIR /app
COPY requirements.txt requirements-tools.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && if [ "$WITH_TOOLS" = "1" ]; then pip install --no-cache-dir -r requirements-tools.txt; fi
COPY asi ./asi
COPY --from=frontend /src/static ./static
RUN useradd -m asi && mkdir -p /data && chown asi /data
USER asi
RUN if [ "$WITH_TOOLS" = "1" ]; then nuclei -update-templates || true; fi
ENV ASI_DB=/data/asi.db ASI_HOST=0.0.0.0 ASI_PORT=8000 ASI_VERSION=$ASI_VERSION
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import json,urllib.request as u; assert json.load(u.urlopen('http://127.0.0.1:8000/api/health'))['status']=='ok'"
CMD ["sh", "-c", "exec uvicorn asi.main:app --host $ASI_HOST --port $ASI_PORT"]
