# Attack Surface Intelligence ze wszystkimi narzędziami. Build: docker compose build
FROM golang:1.23-bookworm AS gotools
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev && rm -rf /var/lib/apt/lists/*
ENV GOBIN=/out CGO_ENABLED=1
# po jednym narzędziu na warstwę; błąd jednego nie blokuje obrazu (aplikacja ma fallbacki)
RUN mkdir -p /out && for p in \
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
      go install "$p@latest" || echo "POMINIĘTO $p"; done

FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends nmap libpcap0.8 git ca-certificates whatweb \
    && git clone --depth 1 https://github.com/testssl/testssl.sh /opt/testssl.sh \
    && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh \
    && apt-get purge -y git && apt-get autoremove -y && rm -rf /var/lib/apt/lists/* /opt/testssl.sh/.git
COPY --from=gotools /out/ /usr/local/bin/
WORKDIR /app
COPY requirements.txt requirements-tools.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-tools.txt
COPY asi ./asi
COPY static ./static
RUN useradd -m asi && mkdir -p /data && chown asi /data
USER asi
RUN nuclei -update-templates || true
ENV ASI_DB=/data/asi.db ASI_HOST=0.0.0.0 ASI_PORT=8000
EXPOSE 8000
CMD ["sh", "-c", "uvicorn asi.main:app --host $ASI_HOST --port $ASI_PORT"]
