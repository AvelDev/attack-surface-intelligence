"""Lekki moduł geolokalizacji IP dla widoku Command Center / 3D Threat Map.
Obsługuje adresy prywatne (lokalizowane w Krakowie / AGH), znane cele testowe
oraz szybki lookup z pamięcią podręczną i fallbackiem bez zależności zewnętrznych.
"""
import ipaddress
import json
import os
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# Domyślnie wyłączone: bez tego adresy publiczne ze skanu (czyli de facto cele/klienci
# zaangażowania) trafiałyby do zewnętrznego ip-api.com w czystym HTTP - ujawnienie danych
# stronie trzeciej. Włączenie jest świadomą decyzją admina, nie zachowaniem domyślnym.
GEO_ONLINE_LOOKUP = os.environ.get("ASI_GEO_ONLINE_LOOKUP", "0") == "1"

# Cache w pamięci podręcznej procesu
_GEO_CACHE = {}

# Znane koordynaty referencyjne
HQ_KRAKOW = {"lat": 50.0664, "lon": 19.9135, "country": "PL", "city": "Kraków (AGH)"}
SCANME_GEO = {"lat": 37.5485, "lon": -121.9886, "country": "US", "city": "Fremont (Linode)"}

# Predefiniowane huby chmurowe jako fallback dla publicznych IP
CLOUD_REGIONS = [
    {"lat": 52.2297, "lon": 21.0122, "country": "PL", "city": "Warszawa"},
    {"lat": 50.1109, "lon": 8.6821, "country": "DE", "city": "Frankfurt"},
    {"lat": 51.5074, "lon": -0.1278, "country": "GB", "city": "Londyn"},
    {"lat": 40.7128, "lon": -74.0060, "country": "US", "city": "Nowy Jork"},
    {"lat": 37.7749, "lon": -122.4194, "country": "US", "city": "San Francisco"},
    {"lat": 35.6762, "lon": 139.6503, "country": "JP", "city": "Tokio"},
    {"lat": 1.3521, "lon": 103.8198, "country": "SG", "city": "Singapur"},
]


def locate_ip(ip_str):
    """Zwraca słownik {lat, lon, country, city, is_hq} dla danego IP."""
    ip_clean = (ip_str or "").split(":")[0].strip()
    if not ip_clean:
        return {**HQ_KRAKOW, "is_hq": True}

    if ip_clean in _GEO_CACHE:
        return _GEO_CACHE[ip_clean]

    # Sprawdzenie czy IP jest prywatne (np. sieć 10.x, 192.168.x) -> baza w Krakowie (AGH)
    try:
        ip_obj = ipaddress.ip_address(ip_clean)
        if not ip_obj.is_global:
            res = {**HQ_KRAKOW, "city": f"LAN ({ip_clean})", "is_hq": True}
            _GEO_CACHE[ip_clean] = res
            return res
    except ValueError:
        pass

    # Cel testowy Nmap
    if ip_clean == "45.33.32.156" or "scanme" in ip_clean:
        res = {**SCANME_GEO, "is_hq": False}
        _GEO_CACHE[ip_clean] = res
        return res

    # Szybka próba zapytania online (ip-api.com) z krótkim timeoutem 1.2s - tylko gdy
    # admin świadomie to włączył (ASI_GEO_ONLINE_LOOKUP=1); domyślnie wyłączone, bo wysyła
    # publiczne IP ze skanu (czyli cele zaangażowania) do zewnętrznej usługi po zwykłym HTTP.
    if GEO_ONLINE_LOOKUP:
        try:
            url = f"http://ip-api.com/json/{ip_clean}?fields=status,countryCode,city,lat,lon"
            req = urllib.request.Request(url, headers={"User-Agent": "asi-agent"})
            with urllib.request.urlopen(req, timeout=1.2) as r:
                data = json.loads(r.read().decode())
                if data.get("status") == "success":
                    res = {
                        "lat": float(data.get("lat", 50.0)),
                        "lon": float(data.get("lon", 19.9)),
                        "country": data.get("countryCode", "EU"),
                        "city": data.get("city", "Cloud"),
                        "is_hq": False
                    }
                    _GEO_CACHE[ip_clean] = res
                    return res
        except Exception:
            pass

    # Deterministyczny fallback na wypadek braku internetu
    h = sum(ord(c) for c in ip_clean) % len(CLOUD_REGIONS)
    reg = CLOUD_REGIONS[h]
    # Delikatne przesunięcie żeby punkty nie nakładały się w 1 pikselu
    offset = ((h * 17) % 10 - 5) * 0.2
    res = {
        "lat": reg["lat"] + offset,
        "lon": reg["lon"] + offset,
        "country": reg["country"],
        "city": reg["city"],
        "is_hq": False
    }
    _GEO_CACHE[ip_clean] = res
    return res


def locate_many(ips):
    """locate_ip() dla wielu adresów naraz, równolegle - sekwencyjnie każdy
    nieocache'owany publiczny adres kosztowałby do 1.2s (zapytanie do ip-api.com),
    co przy skanie z wieloma publicznymi IP zsumowałoby się do dziesiątek sekund."""
    uniq = list(dict.fromkeys(ips))
    with ThreadPoolExecutor(min(16, max(1, len(uniq)))) as ex:
        results = list(ex.map(locate_ip, uniq))
    return dict(zip(uniq, results))
