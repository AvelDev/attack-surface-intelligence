#!/usr/bin/env bash
# Instalacja narzędzi dla ASI na Ubuntu / WSL (Ubuntu). Uruchom: bash scripts/install_tools.sh
set -euo pipefail
sudo apt-get update
sudo apt-get install -y nmap libpcap-dev python3-venv python3-pip golang-go
export PATH="$PATH:$HOME/go/bin"
for pkg in \
  github.com/projectdiscovery/subfinder/v2/cmd/subfinder \
  github.com/projectdiscovery/dnsx/cmd/dnsx \
  github.com/projectdiscovery/httpx/cmd/httpx \
  github.com/projectdiscovery/naabu/v2/cmd/naabu \
  github.com/projectdiscovery/nuclei/v3/cmd/nuclei ; do
  echo ">> go install $pkg"; go install -v "$pkg@latest"
done
"$HOME/go/bin/nuclei" -update-templates || true
grep -q 'go/bin' ~/.bashrc || echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc
echo "Gotowe. Aplikacja sama dodaje ~/go/bin do PATH."
