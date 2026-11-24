"""Co wolno uruchomić: kategorie NSE. Jedno miejsce z tą regułą - używa go API (odmowa) i skan (ponowne sprawdzenie)."""
from ..errors import InvalidInput
from . import scripts

OPEN = ("default", "safe", "discovery", "version", "auth", "vuln", "malware", "intrusive")
GATED = ("brute", "exploit", "dos", "fuzzer")  # ASI_NMAP_INTRUSIVE=1 i rola admin
EXTERNAL = "external"  # wysyła dane o celu do osób trzecich - tylko razem z wywiadem zewnętrznym
NEVER = "broadcast"  # rozsyła w całej sieci lokalnej, czyli poza cele objęte zgodą
CATEGORIES = (*OPEN, *GATED, EXTERNAL)


def allowed(gated, external):
    """Kategorie dozwolone w danym kontekście."""
    return set(OPEN) | (set(GATED) if gated else set()) | ({EXTERNAL} if external else set())


def blocked_by(categories, ok):
    """Kategorie skryptu, które go blokują przy danym zbiorze dozwolonych."""
    return set(categories) & ({*GATED, EXTERNAL, NEVER} - ok)


def check(opts, *, gated, external):
    """InvalidInput, gdy opcje wymagają kategorii spoza dozwolonych."""
    ok = allowed(gated, external)
    for cat in opts.script_categories:
        if cat not in CATEGORIES:
            raise InvalidInput(f"Opcje nmap: nieznana kategoria NSE: {cat}.")
        if cat not in ok:
            raise InvalidInput(_denied(f"kategoria {cat}", {cat}))
    known = scripts.catalog() if opts.scripts else {}
    for name in opts.scripts:
        if name not in known:
            raise InvalidInput(f"Opcje nmap: nie ma skryptu NSE {name}.")
        bad = blocked_by(known[name], ok)
        if bad:
            raise InvalidInput(_denied(f"skrypt {name}", bad))


def _denied(what, cats):
    if NEVER in cats:
        why = "działa na całą sieć lokalną, poza cele skanu"
    elif set(cats) & set(GATED):
        why = "wymaga roli admin i ustawienia ASI_NMAP_INTRUSIVE=1 na serwerze"
    else:
        why = "wysyła dane o celach do osób trzecich, włącz wywiad zewnętrzny"
    return f"Opcje nmap: {what}: {why}."


def restrict(opts, *, gated, external):
    """(opcje bez tego, czego w tym kontekście nie wolno, [usunięte]). Np. bramkę zamknięto po zapisaniu harmonogramu."""
    ok = allowed(gated, external)
    known = scripts.catalog() if opts.scripts else {}
    cats = [c for c in opts.script_categories if c in ok]
    names = [n for n in opts.scripts if n in known and not blocked_by(known[n], ok)]
    dropped = [x for x in (*opts.script_categories, *opts.scripts) if x not in cats and x not in names]
    return (opts.model_copy(update={"script_categories": cats, "scripts": names}) if dropped else opts), dropped


def script_expression(opts):
    """Wartość `--script`. Kategoria nie wciąga skryptów z kategorii, której operator nie wybrał wprost: `vuln` zawiera
    też skrypty oznaczone dos i exploit."""
    parts = []
    if opts.script_categories:
        excluded = [c for c in (*GATED, EXTERNAL, NEVER) if c not in opts.script_categories]
        parts.append(f"({' or '.join(opts.script_categories)}) and not ({' or '.join(excluded)})")
    return ",".join(parts + opts.scripts)
