"""Uruchamianie zewnętrznych narzędzi (bez powłoki) i parsowanie JSON Lines."""
import json
import os
import queue
import shlex
import subprocess
import threading
import time

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


def run_stream(ctx, cmd, timeout, stdin="", on_line=None, poll_s=1.0):
    """Długie narzędzie: linie wyjścia na bieżąco i reakcja na zatrzymanie skanu lub okno czasowe w trakcie pracy
    (ctx.check_time_limit). Proces nigdy nie przeżywa tej funkcji. Zwraca kod wyjścia albo None (limit czasu, brak narzędzia)."""
    assert isinstance(cmd, list) and cmd, "komenda musi być niepustą listą argumentów"
    ctx.log("$ " + shlex.join(cmd))
    try:
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                             errors="replace", env={**os.environ, "PATH": search_path()})
    except OSError as e:
        ctx.log(f"  błąd: {e}")
        return None
    lines = queue.Queue()

    def pump():
        for line in p.stdout:
            lines.put(line.rstrip())
        lines.put(None)

    threading.Thread(target=pump, daemon=True).start()
    deadline = time.monotonic() + timeout
    try:
        try:
            p.stdin.write(stdin)
            p.stdin.close()
        except OSError:
            pass  # narzędzie zakończyło się, zanim przeczytało wejście - powód będzie w jego wyjściu
        while True:
            ctx.check_time_limit()
            if time.monotonic() > deadline:
                ctx.log("  przekroczono limit czasu")
                return None
            try:
                line = lines.get(timeout=poll_s)
            except queue.Empty:
                continue
            if line is None:
                return p.wait(timeout=10)
            if line and on_line:
                on_line(line)
    finally:
        if p.poll() is None:
            p.kill()
            p.wait(timeout=10)


def jsonl(text):
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                pass
