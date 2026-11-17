"""Keyless and keyed HTTP recon sources (crt.sh, Shodan, Censys)."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
from urllib.parse import quote

import httpx

from .config import setting
from .registry import Tool

UA = {"User-Agent": "ReconKit/1.0 (local student lab tool)"}


async def run(tool: Tool, target: str) -> str:
    if tool.api == "crtsh":
        return await _crtsh(target)
    if tool.api == "shodan":
        return await _shodan(target)
    if tool.api == "censys":
        return await _censys(target)
    raise RuntimeError(f"Unknown API tool: {tool.api}")


async def _crtsh(target: str) -> str:
    rows = None
    async with httpx.AsyncClient(timeout=70, headers=UA, follow_redirects=True) as client:
        for attempt in (1, 2):
            try:
                res = await client.get(
                    "https://crt.sh/", params={"q": f"%.{target}", "output": "json"}
                )
                if res.status_code >= 500 and attempt == 1:
                    await asyncio.sleep(2)
                    continue
                res.raise_for_status()
                try:
                    rows = res.json()
                except json.JSONDecodeError:
                    raise RuntimeError(
                        "crt.sh returned non-JSON (the service is often busy). Retry shortly."
                    ) from None
                break
            except httpx.HTTPError as exc:
                if attempt == 2:
                    raise RuntimeError(f"crt.sh request failed: {exc}") from None
                await asyncio.sleep(2)

    if not isinstance(rows, list):
        raise RuntimeError("crt.sh returned an unexpected shape")

    names: dict[str, tuple[str, str]] = {}
    dates: list[str] = []
    for row in rows:
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lower()
            if name:
                names.setdefault(name, (row.get("issuer_name") or "", row.get("not_after") or ""))
        if row.get("not_before"):
            dates.append(row["not_before"])

    lines = [
        "crt.sh - certificate transparency",
        f"Domain: {target}",
        f"Certificates: {len(rows)}   Unique names: {len(names)}",
    ]
    if dates:
        lines.append(f"First seen: {min(dates)[:10]}   Latest expiry: {max(dates)[:10]}")
    lines.append("-" * 72)
    for name in sorted(names)[:800]:
        issuer, expiry = names[name]
        lines.append(f"{name:<48} {issuer[:22]:<24} {expiry[:10]}")
    if len(names) > 800:
        lines.append(f"... {len(names) - 800} more names not shown")
    return "\n".join(lines) + "\n"


async def _shodan(target: str) -> str:
    key = setting("SHODAN_API_KEY")
    if not key:
        raise RuntimeError("SHODAN_API_KEY is not set. Add it to .env and restart ReconKit.")

    is_ip = True
    try:
        ipaddress.ip_address(target)
    except ValueError:
        is_ip = False

    async with httpx.AsyncClient(timeout=40, headers=UA) as client:
        if is_ip:
            res = await client.get(
                f"https://api.shodan.io/shodan/host/{target}", params={"key": key}
            )
        else:
            res = await client.get(
                f"https://api.shodan.io/dns/domain/{target}", params={"key": key}
            )

    if res.status_code != 200:
        detail = res.text[:300]
        if res.status_code == 401:
            detail = "Shodan rejected the API key."
        elif res.status_code == 404 and is_ip:
            detail = "Shodan has no record for this IP."
        elif res.status_code == 429:
            detail = "Shodan rate limit (429). Wait a moment and retry."
        raise RuntimeError(f"Shodan {res.status_code}: {detail}")

    data = res.json()
    if is_ip:
        lines = [
            f"Shodan - host {target}",
            f"Org: {data.get('org', '-')}   ISP: {data.get('isp', '-')}",
            f"ASN: {data.get('asn', '-')}   OS: {data.get('os') or '-'}",
            f"Country: {data.get('country_name', '-')}   Last update: {data.get('last_update', '-')}",
            f"Open ports: {', '.join(str(p) for p in data.get('ports', [])) or 'none'}",
            f"Hostnames: {', '.join(data.get('hostnames', [])) or '-'}",
            f"Tags: {', '.join(data.get('tags', [])) or '-'}",
            f"Known vulns: {', '.join(list(data.get('vulns', {}))[:20]) or 'none reported'}",
            "-" * 72,
        ]
        for banner in (data.get("data") or [])[:40]:
            product = banner.get("product") or ""
            version = banner.get("version") or ""
            port = banner.get("port", "?")
            transport = banner.get("transport", "tcp")
            title = banner.get("http", {}).get("title") if isinstance(banner.get("http"), dict) else ""
            extra = " ".join(part for part in (product, version) if part)
            lines.append(f"{port}/{transport:<5} {extra[:50]:<52} {str(title or '')[:40]}")
    else:
        lines = [
            f"Shodan - DNS for {target}",
            f"Tags: {', '.join(data.get('tags', [])) or '-'}",
            f"Subdomains ({len(data.get('subdomains', []))}):",
        ]
        for sub in sorted(data.get("subdomains", [])):
            lines.append(f"  {sub}.{target}")
        lines.append("-" * 72)
        for record in (data.get("data") or [])[:120]:
            lines.append(
                f"{record.get('type', '?'):<6} {str(record.get('subdomain') or '@'):<28} "
                f"{record.get('value', '')}"
            )
    return "\n".join(lines) + "\n"


async def _censys(target: str) -> str:
    if setting("CENSYS_API_TOKEN"):
        return await _censys_platform(target)
    return await _censys_legacy(target)


async def _resolve_ips(target: str) -> list[str]:
    try:
        ipaddress.ip_address(target)
        return [target]
    except ValueError:
        pass
    infos = await asyncio.get_running_loop().getaddrinfo(
        target, None, type=socket.SOCK_STREAM
    )
    ips: list[str] = []
    for info in infos:
        ip = str(info[4][0])
        if ip not in ips:
            ips.append(ip)
    return ips


def _format_censys_host(resource: dict, ip: str) -> list[str]:
    location = resource.get("location") or {}
    asn = resource.get("autonomous_system") or {}
    lines = [
        f"IP: {ip}",
        f"Location: {location.get('country', '-')} / {location.get('city', '-')}",
        f"ASN: AS{asn.get('asn', '-')} {asn.get('description', '')}".strip(),
    ]
    names = resource.get("names") or []
    if names:
        lines.append("Names: " + ", ".join(str(name) for name in names[:12]))

    services = resource.get("services") or []
    lines.append(f"Services ({len(services)}):")
    for service in services[:30]:
        port = service.get("port", "?")
        transport = service.get("transport_protocol", "tcp")
        protocol = service.get("protocol") or service.get("service_name") or ""
        product = ""
        software = service.get("software") or []
        if software and isinstance(software[0], dict):
            first = software[0]
            product = " ".join(
                str(part)
                for part in (first.get("vendor"), first.get("product"), first.get("version"))
                if part
            )
        title = ""
        http = service.get("http") or {}
        if isinstance(http, dict):
            response = http.get("response") or {}
            if isinstance(response, dict):
                title = response.get("html_title") or ""
            title = title or http.get("title") or ""
        if not title and service.get("banner"):
            title = str(service["banner"])[:60].replace("\n", " ")
        endpoint = f"{port}/{transport}"
        lines.append(
            f"  {endpoint:<12} {str(protocol)[:14]:<16} "
            f"{product[:36]:<38} {str(title)[:40]}"
        )
    return lines


async def _censys_platform(target: str) -> str:
    token = setting("CENSYS_API_TOKEN")
    ips = await _resolve_ips(target)
    if not ips:
        raise RuntimeError(f"Censys: could not resolve {target} to an IP address.")

    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    lines = [
        f"Censys - host data for {target}",
        f"Resolved: {', '.join(ips[:5])}",
        "-" * 72,
    ]
    async with httpx.AsyncClient(timeout=40, headers=UA) as client:
        for ip in ips[:5]:
            url = f"https://api.platform.censys.io/v3/global/asset/host/{quote(ip, safe='')}"
            res = await client.get(url, headers=headers)
            for attempt in range(3):
                if res.status_code != 429:
                    break
                await asyncio.sleep(1.5 * (attempt + 1))
                res = await client.get(url, headers=headers)
            if res.status_code == 404:
                lines.append(f"\n{ip}: no host record")
                continue
            if res.status_code == 429:
                raise RuntimeError(
                    "Censys rate limit (429). Free accounts allow one active "
                    "request; wait a moment and retry."
                )
            if res.status_code in (401, 403):
                raise RuntimeError(
                    f"Censys rejected the token ({res.status_code}). Check the PAT "
                    "and that host lookup is available on your plan."
                )
            if res.status_code != 200:
                raise RuntimeError(f"Censys {res.status_code}: {res.text[:250]}")
            body = res.json()
            result = body.get("result") or {}
            resource = result.get("resource") or result or {}
            lines.append("")
            lines += _format_censys_host(resource, ip)
            await asyncio.sleep(0.3)
    return "\n".join(lines) + "\n"


async def _censys_legacy(target: str) -> str:
    # shortcut: legacy Censys Search v2 API, kept for ID/secret credentials
    api_id = setting("CENSYS_API_ID")
    secret = setting("CENSYS_API_SECRET")
    if not (api_id and secret):
        raise RuntimeError(
            "CENSYS_API_TOKEN is not set. Create a Platform Personal Access Token "
            "and add it to .env (legacy CENSYS_API_ID/CENSYS_API_SECRET also work)."
        )

    async with httpx.AsyncClient(timeout=40, headers=UA) as client:
        try:
            ipaddress.ip_address(target)
            query = f"ip: {target}"
        except ValueError:
            query = f"names: {target}"
        res = await client.get(
            "https://search.censys.io/api/v2/hosts/search",
            params={"q": query, "per_page": 50},
            auth=(api_id, secret),
        )

    if res.status_code in (401, 403):
        raise RuntimeError("Censys rejected the credentials (401/403).")
    if res.status_code == 429:
        raise RuntimeError("Censys rate limit hit (429). Wait and retry.")
    if res.status_code != 200:
        raise RuntimeError(f"Censys {res.status_code}: {res.text[:300]}")

    data = res.json().get("result", {})
    hits = data.get("hits", [])
    lines = [
        f"Censys - hosts matching '{target}'",
        f"Total: {data.get('total', len(hits))}   Showing: {len(hits)}",
        "-" * 72,
    ]
    for hit in hits:
        services = hit.get("services") or []
        ports = ", ".join(
            f"{s.get('port')}/{s.get('transport_protocol', 'tcp')} "
            f"{s.get('service_name') or ''}".strip()
            for s in services[:12]
        )
        location = hit.get("location") or {}
        lines.append(f"{hit.get('ip', '?'):<18} {location.get('country', ''):<18} {ports}")
        if hit.get("name"):
            lines.append(f"    {hit['name']}")
        for name in (hit.get("names") or [])[:6]:
            lines.append(f"    name: {name}")
    if not hits:
        lines.append("No hits.")
    return "\n".join(lines) + "\n"
