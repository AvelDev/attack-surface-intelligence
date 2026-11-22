"""Konfiguracja GVM z UI (asi/gvm_scan.py::get_config/validate_host), dodana żeby nie trzeba
było ustawiać ASI_GVM_* przez zmienne środowiskowe i restart kontenera - formularz w Ustawieniach
(POST /api/settings/gvm) zapisuje host/port/login/hasło do bazy, tym samym wzorcem co już
istniejące ustawienia DefectDojo (zob. test_defectdojo_url_validation.py)."""
import pytest

from asi import gvm_scan


def test_validate_host_rejects_public_accepts_private(monkeypatch):
    with pytest.raises(ValueError):
        gvm_scan.validate_host("1.1.1.1")  # publiczny - hasło GVM idzie plaintextem, nie wolno
    gvm_scan.validate_host("127.0.0.1")  # loopback - ok
    gvm_scan.validate_host("10.0.0.5")  # prywatny - ok


def test_validate_host_rejects_unresolvable_name():
    with pytest.raises(ValueError):
        gvm_scan.validate_host("this-host-does-not-exist.invalid")


def test_get_config_prefers_env_pair_over_db(monkeypatch, temp_db):
    monkeypatch.setattr(gvm_scan, "ENV_HOST", "10.0.0.9")
    monkeypatch.setattr(gvm_scan, "ENV_PASSWORD", "env-secret")
    monkeypatch.setattr(gvm_scan, "ENV_PORT", "9391")
    monkeypatch.setattr(gvm_scan, "ENV_USERNAME", "envadmin")
    with temp_db.conn() as c:
        c.execute("INSERT INTO settings(key, value) VALUES('gvm_host', 'should-not-be-used')")
    host, port, username, password = gvm_scan.get_config()
    assert (host, port, username, password) == ("10.0.0.9", 9391, "envadmin", "env-secret")


def test_get_config_reads_db_pair_when_no_env(monkeypatch, temp_db):
    from asi import crypto
    monkeypatch.setattr(gvm_scan, "ENV_HOST", "")
    monkeypatch.setattr(gvm_scan, "ENV_PASSWORD", "")
    with temp_db.conn() as c:
        c.execute("INSERT INTO settings(key, value) VALUES('gvm_host', '10.0.0.5')")
        c.execute("INSERT INTO settings(key, value) VALUES('gvm_port', '9390')")
        c.execute("INSERT INTO settings(key, value) VALUES('gvm_username', 'admin')")
        c.execute("INSERT INTO settings(key, value) VALUES('gvm_password', ?)", (crypto.enc("db-secret"),))
    host, port, username, password = gvm_scan.get_config()
    assert (host, port, username, password) == ("10.0.0.5", 9390, "admin", "db-secret")


def test_get_config_empty_when_neither_source_complete(monkeypatch, temp_db):
    monkeypatch.setattr(gvm_scan, "ENV_HOST", "")
    monkeypatch.setattr(gvm_scan, "ENV_PASSWORD", "")
    # host w bazie bez hasła (albo odwrotnie) - niekompletna para, NIE liczy się jako skonfigurowane
    with temp_db.conn() as c:
        c.execute("INSERT INTO settings(key, value) VALUES('gvm_host', '10.0.0.5')")
    host, _port, _username, password = gvm_scan.get_config()
    assert not (host and password)
    assert gvm_scan.configured() is False
