"""Wyjątki domenowe. Warstwa API tłumaczy je na kody HTTP (asi/api/__init__.py), logika nie zna HTTP."""


class InvalidInput(ValueError):
    """Dane wejściowe łamią kontrakt (400)."""


class NotFound(LookupError):
    """Obiekt nie istnieje (404)."""


class Conflict(RuntimeError):
    """Operacja niemożliwa w obecnym stanie (409)."""
