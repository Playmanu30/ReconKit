"""Target normalisation and the authorisation allowlist.

Every active tool is gated on the user having explicitly added the target root
to the scope table. Passive lookups (crt.sh, Shodan, Censys) read public data
and are not gated.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlsplit

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _domain(value: str) -> str:
    value = (value or "").strip().lower().rstrip(".")
    if "://" in value:
        value = urlsplit(value).hostname or ""
    if value.startswith("*."):
        value = value[2:]
    if not DOMAIN_RE.match(value):
        raise ValueError("Enter a valid domain, for example example.com")
    return value


def _hostname(value: str) -> str:
    value = (value or "").strip()
    if _is_ip(value):
        return str(ipaddress.ip_address(value))
    return _domain(value)


def normalize(kind: str, raw: str) -> str:
    """Return a canonical target for a tool's target kind (domain | url | host)."""
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Target required")

    if kind == "domain":
        return _domain(raw)

    if kind == "url":
        if "://" not in raw:
            raw = "https://" + raw
        try:
            parts = urlsplit(raw)
            port = parts.port
        except ValueError:
            raise ValueError("Invalid port in URL") from None
        if parts.scheme not in ("http", "https"):
            raise ValueError("Only http:// and https:// targets are supported")
        host = _hostname(parts.hostname or "")
        netloc = f"[{host}]" if ":" in host else host
        if port:
            netloc += f":{port}"
        path = parts.path.rstrip("/")
        query = f"?{parts.query}" if parts.query else ""
        return f"{parts.scheme}://{netloc}{path}{query}"

    return _hostname(raw)


def host_of(value: str) -> str:
    if "://" in value:
        return (urlsplit(value).hostname or "").lower().rstrip(".")
    return value.lower().rstrip(".")


def resolves(host: str) -> bool:
    """False only when the host definitely does not exist in DNS."""
    if _is_ip(host):
        return True
    try:
        socket.getaddrinfo(host, None)
        return True
    except socket.gaierror as exc:
        # A transient DNS failure (EAI_AGAIN) must not block a scan.
        return exc.errno != socket.EAI_NONAME


def allowed(host: str, roots: list[str]) -> bool:
    """True when host equals a scoped root or is a subdomain of one."""
    host = host.lower().rstrip(".")
    for root in roots:
        root = root.lower().rstrip(".")
        if host == root:
            return True
        if not _is_ip(root) and host.endswith("." + root):
            return True
    return False
