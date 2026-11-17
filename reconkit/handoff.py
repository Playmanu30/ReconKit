"""Turn a finished scan's output into a scope-checked target list.

This is the handoff between phases: crt.sh/Amass hostnames become httpx/nuclei
inputs, httpx URLs become Katana inputs, and so on. Only hosts that already pass
the scope allowlist are ever written to a list.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from . import scope
from .config import DATA

URL_RE = re.compile(r"https?://[^\s\"'<>()\[\]{}]+", re.I)
HOST_RE = re.compile(
    r"(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![.\w-])",
    re.I,
)
IP_RE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
TRAILING = ".,;:)]}'\""
MAX_TARGETS = 500


def extract(output: str) -> dict[str, list[str]]:
    """Pull URLs and hostnames out of arbitrary tool output."""
    text = output.replace("*.", "")  # certificate wildcards -> usable names
    urls = sorted({url.rstrip(TRAILING) for url in URL_RE.findall(text)})
    urls = [url for url in urls if len(url) <= 2048][: MAX_TARGETS * 4]

    hosts: set[str] = set()
    for url in urls:
        host = urlsplit(url).hostname
        if host:
            hosts.add(host.lower().rstrip("."))
    for name in HOST_RE.findall(text):
        hosts.add(name.lower().rstrip("."))
    for token in IP_RE.findall(text):
        try:
            hosts.add(str(ipaddress.ip_address(token)))
        except ValueError:
            pass
    return {"urls": urls, "hosts": sorted(hosts)}


def select(data: dict[str, list[str]], roots: list[str], kind: str) -> list[str]:
    """Filter to the scope allowlist and shape targets for a tool."""
    if not roots:
        return []

    urls = [
        url for url in data["urls"]
        if scope.allowed(urlsplit(url).hostname or "", roots)
    ]
    hosts = [host for host in data["hosts"] if scope.allowed(host, roots)]

    if kind == "domain":
        return hosts[:MAX_TARGETS]

    chosen = list(dict.fromkeys(urls))
    seen = {urlsplit(url).hostname for url in chosen}
    for host in hosts:
        if host in seen:
            continue
        chosen.append(f"http://{host}")
        chosen.append(f"https://{host}")
        seen.add(host)
    return chosen[:MAX_TARGETS]


def write_list(targets: list[str]) -> Path:
    folder = DATA / "lists"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{uuid.uuid4().hex}.txt"
    path.write_text("\n".join(targets) + "\n", encoding="utf-8")
    return path
