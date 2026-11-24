#!/usr/bin/env bash
# Instalacja narzędzi dla ASI na Ubuntu / WSL (Ubuntu) / Kali. Uruchom: bash scripts/install_tools.sh
# Każde narzędzie jest opcjonalne - aplikacja ma fallbacki w Pythonie. Błąd jednego nie przerywa reszty.
set -uo pipefail
cd "$(dirname "$0")/.."
sudo apt-get update
sudo apt-get install -y nmap libpcap-dev python3-venv python3-pip golang-go git ruby whatweb 2>/dev/null \
  || sudo apt-get install -y nmap libpcap-dev python3-venv python3-pip golang-go git   # whatweb bywa niedostępny
export PATH="$PATH:$HOME/go/bin"

# narzędzia Go (ProjectDiscovery i inne)
for pkg in \
  github.com/projectdiscovery/subfinder/v2/cmd/subfinder \
  github.com/projectdiscovery/dnsx/cmd/dnsx \
  github.com/projectdiscovery/httpx/cmd/httpx \
  github.com/projectdiscovery/naabu/v2/cmd/naabu \
  github.com/projectdiscovery/nuclei/v3/cmd/nuclei \
  github.com/projectdiscovery/katana/cmd/katana \
  github.com/lc/gau/v2/cmd/gau \
  github.com/tomnomnom/waybackurls \
  github.com/tomnomnom/assetfinder \
  github.com/owasp-amass/amass/v4/... ; do
  echo ">> go install $pkg"; go install -v "$pkg@latest" || echo "!! nie udało się: $pkg"
done
"$HOME/go/bin/nuclei" -update-templates || true

# narzędzia Pythona (do venv aplikacji; run.sh dodaje jego bin do PATH przez interpreter)
VENV="${ASI_VENV:-$HOME/.venvs/asi}"
[ -d "$VENV" ] || python3 -m venv "$VENV"
"$VENV/bin/pip" install -q -r requirements.txt
"$VENV/bin/pip" install -q -r requirements-tools.txt || echo "!! nie udało się zainstalować sslyze/wafw00f/dnsrecon"

# testssl.sh (alternatywa dla sslyze)
if ! command -v testssl.sh >/dev/null && ! command -v testssl >/dev/null; then
  sudo git clone --depth 1 https://github.com/testssl/testssl.sh /opt/testssl.sh \
    && sudo ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh || echo "!! testssl.sh pominięty"
fi

# Bez tego naabu zawsze skanuje w wolnym trybie "connect" (pełny TCP handshake per port) - SYN scan jest rzędem
# wielkości szybszy na dużych zakresach, ale wymaga cap_net_raw, a naabu nie podnosi tego sama nawet jako root.
# Aplikacja wykrywa to automatycznie (asi/scan/tools.py: naabu_can_syn) i bezpiecznie spada do connect scan.
sudo setcap cap_net_raw,cap_net_admin=eip "$HOME/go/bin/naabu" ||   echo "Uwaga: setcap na naabu nie powiódł się - skany portów będą wolniejsze (connect scan)."

grep -q 'go/bin' ~/.bashrc || echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc
echo "Gotowe. Stan narzędzi zobaczysz w aplikacji: Ustawienia > Narzędzia używane przez program."
