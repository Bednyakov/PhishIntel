"""Async adapter for the bundled Go TCP port scanner."""
from __future__ import annotations

import asyncio
import json
import os
import shutil
from pathlib import Path
from typing import Any

from ..config import env, float_value

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BINARY = ROOT / "tools" / "portscanner" / "portscanner"


def _binary() -> str:
    configured = env("PHISHINTEL_PORTSCAN_BINARY")
    return configured or (str(DEFAULT_BINARY) if DEFAULT_BINARY.is_file() else "phishintel-portscanner")


def unavailable(target: str, status: str = "unavailable", error: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": status, "target": target, "ports": [], "open_port_count": 0, "technologies": []}
    if error:
        result["error"] = error
    return result


async def analyze_async(target: str, timeout: float = 8.0) -> dict[str, Any]:
    binary = _binary()
    if not os.path.isabs(binary) and shutil.which(binary) is None:
        return unavailable(target, error="port scanner binary is not built")
    scan_timeout = max(1.0, float_value("PHISHINTEL_PORTSCAN_TIMEOUT", min(45.0, max(5.0, timeout * 3))))
    try:
        process = await asyncio.create_subprocess_exec(
            binary, "--target", target, "--timeout", f"{min(10.0, max(0.25, timeout))}s",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=scan_timeout)
    except asyncio.TimeoutError:
        if 'process' in locals() and process.returncode is None:
            process.kill()
            await process.wait()
        return unavailable(target, "timeout", "port scanner timed out")
    except (OSError, ValueError) as exc:
        return unavailable(target, error=str(exc))
    try:
        result = json.loads(stdout.decode("utf-8", errors="replace"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return unavailable(target, "completed_with_errors", f"invalid scanner JSON: {exc}")
    if process.returncode and result.get("status") == "ok":
        result["status"] = "completed_with_errors"
    if stderr:
        result["stderr"] = stderr.decode("utf-8", errors="replace")[-4000:]
    return result