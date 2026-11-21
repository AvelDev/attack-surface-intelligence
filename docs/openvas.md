# OpenVAS/GVM - stawianie i podłączenie do ASI

Greenbone Community Edition (gvmd/ospd-openvas) stoi w **osobnej** dystrybucji WSL
(`Ubuntu-24.04`), oddzielonej od tej, na której działa reszta ASI (`kali-linux`) - stos
Greenbone (feed sync, redis, postgres, ospd-openvas) jest ciężki i nie powinien konkurować
o zasoby z resztą narzędzi rekonesansu.

## 1. Stos Greenbone (Ubuntu-24.04, Docker Compose)

```
wsl --install -d Ubuntu-24.04 --no-launch     # bez interaktywnego wizarda (brak tty)
wsl -d Ubuntu-24.04 -- bash -c "apt-get update && apt-get install -y ca-certificates curl git socat"
wsl -d Ubuntu-24.04 -- bash -c "curl -fsSL https://get.docker.com | sh"
wsl -d Ubuntu-24.04 -- bash -c "mkdir -p ~/greenbone-community-edition && cd ~/greenbone-community-edition && \
  curl -f -O -L https://greenbone.github.io/docs/latest/_static/compose.yaml"
```

Oficjalny `compose.yaml` wystawia GMP **tylko** po unix sockecie (`/run/gvmd/gvmd.sock`,
wolumen `gvmd_socket_vol`) - nie ma żadnego portu TCP dla GMP. Żeby ASI (inna WSL, więc inny
filesystem namespace - unix socketu nie da się po prostu zamontować między dystrybucjami)
mógł się połączyć po sieci, dorzucony jest `compose.override.yaml` (Docker Compose łączy go
automatycznie z `compose.yaml` w tym samym katalogu) z mostkiem TCP<->socket:

```yaml
services:
  gmp-tcp-bridge:
    image: alpine/socat
    command: ["TCP-LISTEN:9390,fork,reuseaddr", "UNIX-CONNECT:/run/gvmd/gvmd.sock"]
    volumes:
      - gvmd_socket_vol:/run/gvmd
    ports:
      - "9390:9390"
    depends_on:
      gvmd:
        condition: service_started
    deploy:
      restart_policy:
        condition: any
```

Start (pierwszy raz pociągnie kilka GB obrazów + feedów - może trwać długo):

```
cd ~/greenbone-community-edition
docker compose pull
docker compose up -d
docker compose logs -f   # czekaj na "Finished loading VTs.", sync_cert/update_scap OK
```

Domyślny użytkownik to `admin`/`admin` - **zmień hasło**:

```
docker compose exec -u gvmd gvmd gvmd --user=admin --new-password='<silne-haslo>'
```

## 2. Sieć między WSL-kami

Klasyczny (nie-mirrored) WSL2 trzyma wszystkie dystrybucje w jednej VM, więc `kali-linux`
i `Ubuntu-24.04` mają **ten sam adres IP** (sprawdź `hostname -I` w obu). Port `9390`
wystawiony przez `gmp-tcp-bridge` w Ubuntu-24.04 jest więc osiągalny z `kali-linux` pod tym
samym IP. Ten port słucha tylko wewnątrz prywatnej sieci wirtualnej WSL (vEthernet) - GMP po
tym mostku idzie plaintextem (brak TLS), więc `asi/gvm_scan.py` odmawia połączenia (i wysłania
hasła), jeśli `ASI_GVM_HOST` nie jest adresem prywatnym/loopback - to zabezpieczenie przed
przypadkowym wystawieniem danych logowania GVM poza sieć lokalną (np. przez `netsh portproxy`
albo błędną zmianę zmiennej). Dla GVM na realnie zdalnym hoście użyj `TLSConnection`/`SSHConnection`
z python-gvm, nie tego mostku.

## 3. Konfiguracja ASI

Na `kali-linux`, przed `bash run.sh`:

```
export ASI_GVM_HOST=<IP z hostname -I>
export ASI_GVM_PORT=9390
export ASI_GVM_USERNAME=admin
export ASI_GVM_PASSWORD='<silne-haslo-z-kroku-1>'
```

Status widoczny w UI (sekcja "Narzędzia", wpis `openvas`) i w `/api/tools`. Checkbox
"Głęboki skan OpenVAS/GVM" w formularzu nowego skanu odpala zadanie w tle (`asi/gvm_scan.py`) -
osobny wątek i semafor, niezależny od kolejki szybkich skanów, więc kolejne szybkie skany
nie czekają na GVM.
