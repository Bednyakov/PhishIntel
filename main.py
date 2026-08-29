#!/usr/bin/env python3
"""Single entry point for interactive and scripted PhishIntel tools."""

import argparse
import json
import sys
from pathlib import Path

import scan
from app.core.registry import Tool, all_tools, register
from app.tools.domain_scan import DomainScanOptions, run as run_domain_scan


def _progress(update: dict) -> None:
    scan._render_progress(update)


def _domain_cli(args: argparse.Namespace) -> dict:
    return run_domain_scan(DomainScanOptions(args.target, args.profile, args.timeout, None if args.no_progress else _progress, tuple(args.active_tool) if args.active_tool else None))


def _ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or (default or "")


def _interactive_domain() -> dict:
    target = _ask("Домен или URL")
    print("\nПрофиль анализа:")
    profiles = (("quick", "Быстрая проверка"), ("full", "Полный анализ"), ("security", "Аудит безопасности"))
    for index, (_, title) in enumerate(profiles, 1):
        print(f"{index}. {title}")
    selected = _ask("Выберите профиль", "2")
    try:
        profile = profiles[int(selected) - 1][0]
    except (ValueError, IndexError):
        raise ValueError("некорректный номер профиля")
    active_tools: tuple[str, ...] | None = None
    if profile == "security" and _ask("Запустить активные сканеры? (может создавать сетевую нагрузку)", "y").lower() not in ("y", "yes", "д", "да"):
        profile = "full"
    return run_domain_scan(DomainScanOptions(target, profile, float(_ask("Таймаут сетевых запросов", "8.0")), _progress, active_tools))


def _register_tools() -> None:
    if not all_tools():
        register(Tool("domain-scan", "Анализ домена", "Проверка домена и оценка фишингового риска.", _interactive_domain, _domain_cli))


def _save_report(report: dict, output_dir: str = "reports") -> Path:
    path = scan._report_path(output_dir, report["target"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="PhishIntel OSINT toolkit")
    subparsers = parser.add_subparsers(dest="tool")
    domain = subparsers.add_parser("domain-scan", help="анализ домена")
    domain.add_argument("target", help="домен или URL")
    domain.add_argument("--profile", choices=("quick", "full", "security"), default="full")
    domain.add_argument("--timeout", type=float, default=8.0)
    domain.add_argument("--no-progress", action="store_true")
    domain.add_argument("--active-tool", action="append", choices=("nmap", "nuclei", "zap"))
    domain.add_argument("--stdout", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    _register_tools()
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.tool is None:
            print("\nPhishIntel — выберите инструмент:\n")
            for index, tool in enumerate(all_tools(), 1):
                print(f"{index}. {tool.title} — {tool.description}")
            print("0. Выход")
            choice = _ask("Ваш выбор", "0")
            if choice == "0":
                return 0
            tool = all_tools()[int(choice) - 1]
            report = tool.run_interactive()
            path = _save_report(report)
            print(f"Проверка домена {report['target']} завершена.")
            print(f"Отчёт сохранён: {path}")
            return 0
        tool = next((item for item in all_tools() if item.name == args.tool), None)
        if tool is None:
            parser.error(f"неизвестный инструмент: {args.tool}")
        report = tool.run_cli(args)
        if args.stdout:
            print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        else:
            path = _save_report(report)
            print(f"Проверка домена {report['target']} завершена.")
            print(f"Отчёт сохранён: {path}")
        return 0
    except (ValueError, OSError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())