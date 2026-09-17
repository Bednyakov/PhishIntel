"""Compact Russian HTML renderer for JSON reports."""

from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _text(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "да" if value else "нет"
    if isinstance(value, (dict, list)):
        return str(value)
    return str(value)


def _safe_name(target: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", target).strip("._")
    return value or "report"


def report_path(report: dict[str, Any], output_dir: str | Path = "reports") -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    return Path(output_dir) / f"{_safe_name(str(report.get('target', 'report')))}_{timestamp}.html"


def _row(label: str, value: Any) -> str:
    return f"<div class=\"row\"><span>{html.escape(label)}</span><strong>{html.escape(_text(value))}</strong></div>"


def render(report: dict[str, Any]) -> str:
    """Return a concise, self-contained Russian HTML report."""
    target = _text(report.get("target"))
    summary = report.get("summary", {})
    contacts = report.get("contacts", {})
    external = report.get("external_resources", {})
    redirects = report.get("redirects") or report.get("domain", {}).get("redirects", {})
    chain = redirects.get("chain", []) if isinstance(redirects, dict) else []
    contact_summary = "".join(
        f"<li><b>{html.escape(str(key))}</b>: {len(value) if isinstance(value, list) else html.escape(_text(value))}</li>"
        for key, value in contacts.items()
    ) or "<li>Не обнаружены</li>"
    contact_details = "".join(
        f"<li><b>{html.escape(str(key))}</b><ul>"
        f"{''.join(f'<li>{html.escape(_text(item))}</li>' for item in value) if isinstance(value, list) and value else f'<li>{html.escape(_text(value))}</li>'}"
        f"</ul></li>"
        for key, value in contacts.items()
    ) or "<li>Не обнаружены</li>"
    external_items = "".join(
        f"<li><b>{html.escape(str(key))}</b>: {len(value) if isinstance(value, list) else html.escape(_text(value))}</li>"
        for key, value in external.items()
    ) or "<li>Не обнаружены</li>"
    redirect_items = "".join(
        f"<li><code>{html.escape(_text(item.get('status_code')))}</code> "
        f"{html.escape(_text(item.get('from')))} → {html.escape(_text(item.get('to')))}</li>"
        for item in chain
    ) or "<li>Переходов нет</li>"
    final_url = redirects.get("final_url") if isinstance(redirects, dict) else None

    return f"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhishIntel // {html.escape(target)}</title>
<style>
:root {{ color-scheme: dark; --bg:#07100d; --panel:#0d1b16; --line:#1d4d3a; --green:#39ff88; --muted:#8eb5a0; --red:#ff5874; }}
* {{ box-sizing:border-box; }} body {{ margin:0; background:radial-gradient(circle at top,#123126 0,#07100d 45%); color:#e2f5e8; font:16px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace; }}
main {{ max-width:1040px; margin:0 auto; padding:32px 18px 54px; }} header {{ border-bottom:1px solid var(--line); padding-bottom:20px; margin-bottom:20px; }}
h1 {{ color:var(--green); font-size:clamp(24px,5vw,42px); margin:0 0 8px; text-shadow:0 0 14px #39ff8855; }} h1::before {{ content:'> '; }} h2 {{ color:var(--green); font-size:19px; margin:0 0 14px; }}
.target {{ color:var(--muted); overflow-wrap:anywhere; }} .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:16px; }}
section {{ background:#0d1b16dd; border:1px solid var(--line); border-radius:8px; padding:18px; margin-bottom:16px; box-shadow:0 0 22px #0008; }}
.row {{ display:flex; justify-content:space-between; gap:16px; border-bottom:1px dashed #276249; padding:7px 0; }} .row:last-child {{ border-bottom:0; }} .row span {{ color:var(--muted); }} strong {{ color:#fff; text-align:right; }}
ul {{ margin:0; padding-left:22px; }} li {{ margin:7px 0; overflow-wrap:anywhere; }} code {{ color:#101a13; background:var(--green); padding:1px 5px; border-radius:3px; }} .risk {{ color:var(--red); }} footer {{ color:var(--muted); font-size:12px; margin-top:28px; }}
</style>
</head>
<body><main>
<header><h1>PhishIntel // отчёт разведки</h1><div class="target">цель: {html.escape(target)}</div></header>
<div class="grid">
<section><h2>Сводка</h2>{_row('Страниц проверено', summary.get('pages_visited', '—'))}</section>
<section><h2>Контакты</h2><ul>{contact_summary}</ul></section>
<section><h2>Внешние ресурсы</h2><ul>{external_items}</ul></section>
</div>
<section><h2>Цепочка перенаправлений</h2>{_row('Переходов', redirects.get('count', len(chain)) if isinstance(redirects, dict) else 0)}{_row('Конечный URL', final_url)}<ul>{redirect_items}</ul></section>
<section><h2>Контактная информация</h2><ul>{contact_details}</ul></section>
<footer>Сформировано PhishIntel • {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</footer>
</main></body></html>
"""


def save(report: dict[str, Any], output_dir: str | Path = "reports") -> Path:
    path = report_path(report, output_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(report), encoding="utf-8")
    return path