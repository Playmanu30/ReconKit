"""Paths, env loading and tiny settings helpers."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(os.environ.get("RECON_DATA") or (ROOT / "data"))
SHOTS = DATA / "screenshots"
WEB = ROOT / "web"
WORDLISTS = ROOT / "wordlists"
DB_PATH = Path(os.environ.get("RECON_DB") or (DATA / "reconkit.db"))


def load_env() -> None:
    """Read .env next to the app without overriding real environment variables."""
    path = ROOT / ".env"
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


def ensure_dirs() -> None:
    for folder in (DATA, SHOTS):
        folder.mkdir(parents=True, exist_ok=True)


def prefer_local_bins() -> None:
    """Prefer user-installed engines over same-named Python shims.

    Go tools land in ~/go/bin, pipx apps in ~/.local/bin, and a virtualenv
    installs its scripts next to python.exe. The Python `httpx` package ships an
    `httpx` console script, so PATH order decides which engine runs.
    """
    candidates = [
        Path.home() / "go" / "bin",
        Path.home() / ".local" / "bin",
        Path(sys.executable).parent,
        Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Nmap",
    ]
    parts = [p for p in os.environ.get("PATH", "").split(os.pathsep) if p]
    normalized = {str(p).rstrip("\\/").lower() for p in candidates}
    parts = [p for p in parts if p.rstrip("\\/").lower() not in normalized]
    existing = [str(p) for p in candidates if p.is_dir()]
    os.environ["PATH"] = os.pathsep.join([*existing, *parts])


def setting(*names: str, default: str = "") -> str:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return default
