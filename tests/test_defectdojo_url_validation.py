"""Regresja SSRF/eksfiltracji przez URL integracji DefectDojo (asi/defectdojo.py::validate_url).

Rola 'add_remove_modify' nie może ustawić tego URL-a na wewnętrzny/prywatny adres -
to by pozwoliło po cichu przekierować eksport ustaleń ze WSZYSTKICH skanów gdzie indziej
(stąd też endpoint jest admin-only, zob. tests/test_rbac.py).
"""
import pytest

from asi import defectdojo


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8000/api/v2",
    "http://localhost/api/v2",
    "http://169.254.169.254/latest/meta-data",  # link-local - metadata cloud providerów
    "http://10.0.0.5/api/v2",
    "http://192.168.1.10/api/v2",
    "ftp://example.org/api/v2",  # zły scheme
    "not-a-url",
])
def test_validate_url_rejects_private_and_malformed(url):
    with pytest.raises(ValueError):
        defectdojo.validate_url(url)


def test_validate_url_accepts_public_address():
    # IP literalny - brak zapytania DNS, deterministyczne offline.
    defectdojo.validate_url("http://1.1.1.1:8443/api/v2")
