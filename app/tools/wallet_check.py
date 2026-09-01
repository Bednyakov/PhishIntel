"""User-facing cryptocurrency wallet check tool."""
from __future__ import annotations

import argparse
import json

from ..analyzers import wallet


def print_report(report: dict) -> None:
    print("\nWallet Check\n============")
    print(f"Address: {report['target']}")
    print(f"Blockchain: {report.get('blockchain') or 'unknown'}")
    print(f"Address type: {report.get('address_type') or 'unknown'}")
    print(f"Valid: {'yes' if report['valid'] else 'no'}")
    for key, value in report["metrics"].items():
        print(f"{key.replace('_', ' ').title()}: {json.dumps(value, ensure_ascii=False) if isinstance(value, dict) else value}")
    print(f"Data source: {report['source'].get('provider')} ({report['source']['status']})")


def run(address: str, timeout: float = 8.0, show_report: bool = True) -> dict:
    report = wallet.analyze(address, timeout=timeout)
    if show_report:
        print_report(report)
    return report


def run_cli(args: argparse.Namespace) -> dict:
    return run(args.address, args.timeout, not args.stdout)


def interactive() -> dict:
    return run(input("Wallet address: ").strip())