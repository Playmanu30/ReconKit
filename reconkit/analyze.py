"""Scan analysis: an OpenAI-compatible LLM when configured, rules otherwise.

No output leaves the machine unless AI_API_KEY is set in .env.
"""

from __future__ import annotations

import re

import httpx

from .config import setting
from .registry import Tool

MAX_INPUT = 9000

PORTS = re.compile(r"^(\d{1,5})/(tcp|udp)\s+open\s+(\S+)?\s*(.*)$", re.M)
HTTP = re.compile(r"https?://[^\s\"'<>)\]]+")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
NUCLEI = re.compile(r"\[(critical|high|medium|low)\]", re.I)
UNRESOLVED = re.compile(r"failed to resolve|no address found for host|nxdomain", re.I)
FFUF = re.compile(r"^(\S+)\s+\[Status:\s*(\d+)", re.M)
GOBUSTER = re.compile(r"^(\S+)\s+\(Status:\s*(\d+)\)", re.M)

NEXT = {
    "amass": "Resolve the new names with dnsx, then probe live hosts with httpx.",
    "theharvester": "Check which emails appear in breach data, and confirm them before any phishing test.",
    "spiderfoot": "Pivot on the highest-signal nodes (hosts, emails, netblocks) and verify each manually.",
    "bbot": "Feed the discovered hosts into httpx, then katana for endpoints.",
    "nmap": "Probe the HTTP ports with httpx -status-code -title, then run nuclei with tags cve,default-login.",
    "dnsx": "Send resolved hosts to httpx to find live web services.",
    "httpx": "Crawl each live site with katana, fuzz directories with ffuf, then run nuclei.",
    "katana": "Filter interesting paths, then fuzz parameters and check for exposed panels or APIs.",
    "gau": "Look for old endpoints, backups and API versions in the archive, then request them live.",
    "ffuf": "Inspect every 200/401/403 finding manually; confirm nothing is a soft-404 before reporting.",
    "gobuster": "Inspect non-404 results manually and check for directory listing or backup files.",
    "nuclei": "Re-run confirmed high/critical findings with a single template and verify by hand.",
    "gowitness": "Review the screenshots for login panels, default installs and error pages.",
    "crtsh": "Resolve the hostnames with dnsx and probe them with httpx.",
    "shodan": "Pivot on exposed services and match versions to CVEs before reporting.",
    "censys": "Pivot on the certificates and exposed services, then verify hosts directly.",
}


def _rules(tool: Tool | None, target: str, output: str, status: str) -> str:
    ports = PORTS.findall(output)
    urls = sorted(set(HTTP.findall(output)))
    emails = sorted(set(e for e in EMAIL.findall(output) if not e.lower().endswith(".png")))
    cves = sorted({c.upper() for c in CVE.findall(output)})
    nuclei_hits = NUCLEI.findall(output) if tool and tool.id == "nuclei" else []
    ffuf_hits = FFUF.findall(output)
    gobuster_hits = GOBUSTER.findall(output)
    path_hits = [path for path, _ in ffuf_hits] + [path for path, _ in gobuster_hits]
    # `ffuf -s` prints only matching paths, with no status column.
    if tool and tool.id == "ffuf" and not ffuf_hits:
        path_hits += [
            line.strip()
            for line in output.splitlines()
            if line.strip() and not line.startswith("[")
        ][:40]
    path_hits = list(dict.fromkeys(path_hits))
    sev_counts: dict[str, int] = {}
    for sev in nuclei_hits:
        sev_counts[sev.lower()] = sev_counts.get(sev.lower(), 0) + 1

    name = tool.name if tool else "scan"
    lines = [
        f"RULE-BASED SUMMARY - {name} - {target}",
        f"Status: {status}    Output: {len(output.splitlines())} lines",
        "",
        "WHAT IT FOUND",
    ]

    found = False
    if ports:
        shown = ", ".join(
            f"{p}/{proto} {svc or ''}".strip() for p, proto, svc, _ in ports[:24]
        )
        lines.append(f"- {len(ports)} open ports: {shown}")
        found = True
    if path_hits:
        shown = ", ".join(path_hits[:14])
        lines.append(f"- {len(path_hits)} paths found: {shown}")
        found = True
    if sev_counts:
        counts = ", ".join(f"{n} {s}" for s, n in sorted(sev_counts.items()))
        lines.append(f"- nuclei findings: {counts}")
        found = True
    if urls:
        lines.append(f"- {len(urls)} unique URLs, e.g. {', '.join(urls[:5])}")
        found = True
    if emails:
        lines.append(f"- {len(emails)} email addresses, e.g. {', '.join(emails[:5])}")
        found = True
    if cves:
        lines.append(f"- CVEs referenced: {', '.join(cves[:10])}")
        found = True
    if UNRESOLVED.search(output):
        lines.append(
            "- DNS lookup failed: the target hostname does not exist (NXDOMAIN). "
            "Check the spelling, or use an IP address."
        )
        found = True
    if not found:
        lines.append("- No structured signals recognised. Read the raw output.")

    highlights = [
        line.strip()
        for line in output.splitlines()
        if NUCLEI.search(line) or "[FINDING]" in line
    ][:10]
    if highlights:
        lines += ["", "HIGHLIGHTS"]
        lines += [f"- {ln[:220]}" for ln in highlights]

    lines += ["", "NEXT STEPS"]
    if tool and tool.id in NEXT:
        lines.append(f"- {NEXT[tool.id]}")
    lines.append("- Validate every finding manually: recon output contains false positives.")
    lines.append("- Record the asset, evidence and timestamp before writing any report.")
    return "\n".join(lines)


def _clip(text: str) -> str:
    if len(text) <= MAX_INPUT:
        return text
    return text[:6000] + "\n...[middle of output clipped]...\n" + text[-2500:]


async def _llm(tool: Tool | None, target: str, output: str, status: str, key: str) -> str:
    base = setting("AI_BASE_URL", default="https://api.openai.com/v1").rstrip("/")
    model = setting("AI_MODEL", default="gpt-4o-mini")
    payload = {
        "model": model,
        "temperature": 0.2,
        "max_tokens": 500,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a senior reconnaissance analyst helping a student on an "
                    "authorised security assessment. Be concrete and terse. Use plain "
                    "text with the section labels FINDINGS, RISK, NEXT. Only state what "
                    "the output supports; never invent hosts, ports, vulnerabilities, "
                    "credentials or versions. Do not reinterpret values: a path is a "
                    "path, a hostname is a hostname, an email is an email. If nothing "
                    "is evidenced, say so."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Tool: {tool.name if tool else 'unknown'}\n"
                    f"Target: {target}\nStatus: {status}\n\n"
                    "Analyse this run. In FINDINGS list the concrete assets and "
                    "exposures present in the output. In RISK note only what the output "
                    "evidences; if nothing is evidenced, write 'No risk is evidenced by "
                    "this run.' In NEXT give up to three specific follow-up checks. "
                    "Keep it under 200 words.\n\n"
                    f"--- output ---\n{output}"
                ),
            },
        ],
    }
    async with httpx.AsyncClient(timeout=180) as client:
        res = await client.post(
            f"{base}/chat/completions",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json=payload,
        )
    if res.status_code != 200:
        raise RuntimeError(f"{res.status_code} {res.text[:160]}")
    data = res.json()
    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        raise RuntimeError("unexpected response shape") from None
    return str(content).strip()


async def analyze(
    tool: Tool | None, target: str, output: str, status: str
) -> tuple[str, str]:
    if not output.strip():
        if status == "done":
            return (
                f"Scan finished with no output: {target} did not respond or nothing "
                "matched. Check the target resolves and is reachable, then retry.",
                "rules",
            )
        return "Nothing to analyse yet.", "rules"
    key = setting("AI_API_KEY", "OPENAI_API_KEY")
    if key:
        try:
            return await _llm(tool, target, _clip(output), status, key), "ai"
        except Exception as exc:  # noqa: BLE001 - degrade instead of failing
            note = f"AI request failed ({exc}). Rule-based summary follows.\n\n"
            return note + _rules(tool, target, output, status), "rules"
    return _rules(tool, target, output, status), "rules"
