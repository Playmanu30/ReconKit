"""Binary discovery and version probes for the installed engines."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .config import setting
from .registry import Tool

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
_CACHE: dict[str, tuple[float, dict]] = {}
_LOCK = threading.Lock()
_TTL = 60.0
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def resolve(tool: Tool) -> str | None:
    override = setting(f"RECON_{tool.id.upper()}")
    if override:
        path = Path(override)
        if path.is_file():
            return str(path)
        return shutil.which(override)
    for name in tool.binary:
        found = shutil.which(name)
        if found:
            return found
    return None


def _probe(path: str, args: tuple[str, ...]) -> str:
    try:
        done = subprocess.run(
            [path, *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=6,
            creationflags=CREATE_NO_WINDOW,
        )
        text = (done.stdout or "") + (done.stderr or "")
    except Exception as exc:  # noqa: BLE001 - probes are best effort
        return f"(probe failed: {exc.__class__.__name__})"
    return ANSI.sub("", text)


def _api_status(tool: Tool) -> dict:
    if tool.api == "crtsh":
        return {"status": "ready", "path": "", "version": "public API", "message": ""}
    if tool.api == "shodan":
        has = bool(setting("SHODAN_API_KEY"))
        return {
            "status": "ready" if has else "needs_key",
            "path": "", "version": "API key found" if has else "",
            "message": "" if has else "Add SHODAN_API_KEY to .env, then restart.",
        }
    if tool.api == "censys":
        token = bool(setting("CENSYS_API_TOKEN"))
        legacy = bool(setting("CENSYS_API_ID") and setting("CENSYS_API_SECRET"))
        has = token or legacy
        return {
            "status": "ready" if has else "needs_key",
            "path": "",
            "version": ("Platform token found" if token else "legacy ID/secret found") if has else "",
            "message": "" if has else "Add CENSYS_API_TOKEN (free Platform PAT) to .env, then restart.",
        }
    return {"status": "ready", "path": "", "version": "", "message": ""}


def check(tool: Tool, refresh: bool = False) -> dict:
    if tool.api:
        return _api_status(tool)

    with _LOCK:
        cached = _CACHE.get(tool.id)
        if cached and not refresh and time.monotonic() - cached[0] < _TTL:
            return cached[1]

    path = resolve(tool)
    if not path:
        result = {
            "status": "missing",
            "path": "",
            "version": "",
            "message": "Not found on PATH.",
        }
    else:
        raw = _probe(path, tool.version)
        lines = [line.strip() for line in raw.splitlines() if line.strip()]
        candidates = [
            line for line in lines
            if len(line) <= 120 and re.search(r"\d+\.\d+", line)
        ]
        version = next((line for line in candidates if "version" in line.lower()), "")
        if not version and candidates:
            version = candidates[0]
        if not version and lines:
            version = lines[0]
        version = version.strip("* ").strip()[:120]
        if os.name == "nt" and not tool.windows_ok:
            result = {
                "status": "unsupported",
                "path": path,
                "version": version,
                "message": f"{tool.name} does not run on native Windows. Use WSL or Linux.",
            }
            with _LOCK:
                _CACHE[tool.id] = (time.monotonic(), result)
            return result
        result = {"status": "ready", "path": path, "version": version, "message": ""}
        if tool.match and raw and re.search(tool.match, raw, re.I | re.M):
            detail = (
                f"This does not look like {tool.name}. Install the expected tool "
                f"or set RECON_{tool.id.upper()}."
            )
            result = {
                "status": "conflict" if tool.strict_match else "unverified",
                "path": path,
                "version": version,
                "message": detail,
            }

    with _LOCK:
        _CACHE[tool.id] = (time.monotonic(), result)
    return result


def check_all(tools: tuple[Tool, ...], refresh: bool = False) -> dict[str, dict]:
    workers = max(1, min(8, len(tools)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda t: check(t, refresh), tools))
    return {tool.id: result for tool, result in zip(tools, results)}
