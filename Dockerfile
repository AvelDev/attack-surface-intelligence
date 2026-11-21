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

FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap libpcap0.8 libcap2-bin ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Oficjalny obraz golang ustawia GOPATH=/go (nie ~/go jak w naszych środowiskach WSL) -
# stąd go install ląduje w /go/bin, nie /root/go/bin.
COPY --from=tools /go/bin/* /usr/local/bin/
# Pozwala na szybszy SYN scan (naabu -s s) zamiast domyślnego, wolnego connect scan - w
# praktyce i tak nadpisane przez cap_add w docker-compose.yml (kontener i tak chodzi jako
# root), ale zostaje jako zabezpieczenie na wypadek uruchomienia obrazu inaczej (np. z
# dodanym tylko NET_RAW dla non-root usera).
RUN setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/naabu || true

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY asi ./asi
COPY static ./static

ENV ASI_HOST=0.0.0.0 \
    ASI_PORT=8000 \
    ASI_DB=/data/asi.db \
    ASI_SECRET_KEY_FILE=/data/secret.key \
    PYTHONUNBUFFERED=1

VOLUME ["/data"]
EXPOSE 8000
CMD ["uvicorn", "asi.main:app", "--host", "0.0.0.0", "--port", "8000"]
