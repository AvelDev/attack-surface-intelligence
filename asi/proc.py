"""Uruchamianie zewnętrznych narzędzi (bez powłoki) i parsowanie JSON Lines."""
import json
import subprocess


def run_cmd(ctx, cmd, timeout, stdin=None):
    ctx.log("$ " + " ".join(cmd))
    try:
        r = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0 and not r.stdout:
            ctx.log(f"  kod wyjścia {r.returncode}: {r.stderr.strip()[-300:]}")
        return r.stdout
    except subprocess.TimeoutExpired as e:
        ctx.log("  przekroczono limit czasu")
        o = e.stdout
        return o.decode(errors="ignore") if isinstance(o, bytes) else (o or "")
    except Exception as e:  # noqa: BLE001
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
