"""Prezentacja wyników poza UI: raport HTML do druku/PDF i eksport CSV."""
import csv
import html
import io
import time

from . import domain

CSV_FIELDS = ("severity", "title", "asset", "detail", "fix", "source")
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")

REPORT_CSS = ("body{font:16px/1.55 'Segoe UI',Arial,sans-serif;color:#17202e;max-width:52rem;margin:2rem auto;padding:0 1rem}"
              "h1{font-size:1.6rem;margin:0 0 .3rem}h2{font-size:1.2rem;margin:1.8rem 0 .5rem}"
              ".meta{color:#44505f;margin:0 0 1rem}.box{border:2px solid;border-radius:6px;padding:1rem 1.2rem;margin:1rem 0}"
              ".bad{background:#fdecec;border-color:#b3202a}.warn{background:#fff3d1;border-color:#a56a00}"
              ".good{background:#e7f4ea;border-color:#1e7b3c}.box b.t{font-size:1.25rem;display:block}"
              ".f{border:1px solid #c6cdd8;border-radius:6px;padding:.8rem 1rem;margin:.7rem 0;break-inside:avoid}"
              ".f h3{margin:0 0 .3rem;font-size:1.05rem}.tag{display:inline-block;font-weight:700;font-size:.8rem;"
              "padding:.1rem .5rem;border-radius:4px;background:#17202e;color:#fff;margin-right:.5rem}"
              ".f p{margin:.2rem 0}.f .k{font-weight:700}code{font:.85rem Consolas,monospace;word-break:break-all}"
              "button{font:inherit;font-weight:600;padding:.6rem 1.2rem;border:2px solid #0b4f9e;background:#0b4f9e;"
              "color:#fff;border-radius:6px;cursor:pointer}@media print{button{display:none}body{margin:0}}")


def _csv_safe(value):
    """Ochrona przed CSV injection - dane pochodzą ze skanowanych (niezaufanych) hostów."""
    s = str(value)
    return "'" + s if s.startswith(_FORMULA_START) else value


def findings_csv(findings):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_FIELDS)
    for f in findings:
        w.writerow([_csv_safe(f[k]) for k in CSV_FIELDS])
    return buf.getvalue()


def _finding_html(f):
    e = html.escape
    return (f"<div class=f><h3><span class=tag>{e(domain.SEV_LABEL.get(f['severity'], f['severity']))}</span>{e(f['title'])}</h3>"
            f"<p><span class=k>Dotyczy:</span> <code>{e(f['asset'])}</code></p>"
            + (f"<p><span class=k>Co zrobić:</span> {e(f['fix'])}</p>" if f["fix"] else "")
            + f"<p><span class=k>Termin:</span> {e(domain.SEV_WHEN.get(f['severity'], ''))}</p></div>")


def html_report(scan, assets, findings):
    """Samodzielna strona HTML. Każda wartość z bazy jest escapowana (pochodzi ze skanowanych hostów)."""
    e = html.escape
    score = scan["score"] or 0
    counts = domain.count_by_severity(findings)
    urgent = sum(counts.get(s, 0) for s in domain.URGENT)
    v = domain.verdict(score, counts)
    when = time.strftime("%d.%m.%Y %H:%M", time.localtime(scan["created"])) if scan.get("created") else ""
    items = "".join(_finding_html(f) for f in findings) or "<p>Nie znaleziono żadnych uwag.</p>"
    return (f"<!doctype html><html lang=pl><meta charset=utf-8><title>Raport z sprawdzenia: {e(scan['target'])}</title>"
            f"<style>{REPORT_CSS}</style>"
            f"<p><button onclick=print()>Drukuj lub zapisz jako PDF</button></p>"
            f"<h1>Raport z sprawdzenia bezpieczeństwa strony</h1>"
            f"<p class=meta>Strona: <b>{e(scan['target'])}</b> · sprawdzenie nr {scan['id']} · {e(when)}</p>"
            f"<div class='box {v['tone']}'><b class=t>{e(v['title'])}</b>{e(v['text'])}<br>Ocena ryzyka: <b>{score} na 100</b> "
            f"(im niżej, tym lepiej) · uwag: <b>{len(findings)}</b> · w tym pilnych: <b>{urgent}</b></div>"
            f"<h2>Co należy naprawić</h2>{items}"
            f"<h2>O tym raporcie</h2><p>Raport obejmuje wyłącznie to, co jest widoczne z internetu "
            f"({len(assets)} wykrytych elementów). Program niczego nie zmienia na sprawdzanej stronie. "
            f"Wynik nie zastępuje audytu bezpieczeństwa.</p>")
