"""Uruchamianie zewnętrznych narzędzi (bez powłoki) i parsowanie JSON Lines."""
import json
import os
import subprocess

from .tools import search_path


def run_cmd(ctx, cmd, timeout, stdin=None):
    """Uruchamia listę argumentów (nigdy przez powłokę). Zwraca stdout; błędy trafiają do logu skanu, nie wyżej."""
    assert isinstance(cmd, list) and cmd, "komenda musi być niepustą listą argumentów"
    ctx.log("$ " + " ".join(cmd))
    try:
        r = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout, check=False,
                           env={**os.environ, "PATH": search_path()})
        if r.returncode != 0 and not r.stdout:
            ctx.log(f"  kod wyjścia {r.returncode}: {r.stderr.strip()[-300:]}")
        return r.stdout
    except subprocess.TimeoutExpired as e:
        ctx.log("  przekroczono limit czasu")
        o = e.stdout
        return o.decode(errors="ignore") if isinstance(o, bytes) else (o or "")
    except Exception as e:  # noqa: BLE001 - brak narzędzia lub błąd systemu nie przerywa skanu
        ctx.log(f"  błąd: {e}")
        return ""


def jsonl(text):
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                pass
