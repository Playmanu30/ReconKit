"""Tool registry: one entry per engine, with its flags in one place.

Adding a tool means adding one Tool() below. CLI tools return argv items after
the binary; HTTP tools set api= and are handled by external.py.
"""

from __future__ import annotations

import ipaddress
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .config import ROOT, SHOTS


@dataclass(frozen=True)
class Opt:
    key: str
    label: str
    kind: str = "text"  # text | select | bool
    default: Any = ""
    choices: tuple[str, ...] = ()
    hint: str = ""


@dataclass(frozen=True)
class Tool:
    id: str
    name: str
    group: str
    blurb: str
    target: str  # domain | url | host
    build: Callable[[str, dict[str, Any]], list[str]] | None = None
    list_build: Callable[[str, dict[str, Any]], list[str]] | None = None
    binary: tuple[str, ...] = ()
    options: tuple[Opt, ...] = ()
    passive: bool = False
    api: str = ""  # crtsh | shodan | censys
    install: str = ""
    docs: str = ""
    note: str = ""
    timeout: int = 600
    stdin: bool = False
    windows_ok: bool = True
    version: tuple[str, ...] = ("-version",)
    match: str = ""  # expected regex in version output
    strict_match: bool = False


def _wordlist(value: str) -> str:
    path = Path(value)
    if not path.is_absolute():
        path = ROOT / path
    if not path.is_file():
        raise ValueError(f"Wordlist not found: {path}")
    return str(path)


# ---------------------------------------------------------------- builders


def _amass(t: str, o: dict) -> list[str]:
    args = ["enum", "-d", t]
    if o["mode"] == "passive":
        args.append("-passive")
    return args


def _harvester(t: str, o: dict) -> list[str]:
    args = ["-d", t, "-b", o["sources"] or "all"]
    if str(o["limit"]).isdigit():
        args += ["-l", str(o["limit"])]
    return args


def _bbot(t: str, o: dict) -> list[str]:
    return ["-t", t, "-p", o["preset"], "-y", "--no-color"]


def _spiderfoot(t: str, o: dict) -> list[str]:
    try:
        ipaddress.ip_address(t)
        kind = "IP_ADDRESS"
    except ValueError:
        kind = "DOMAIN_NAME"
    return ["-s", t, "-t", kind, "-m", o["modules"] or "all"]


def _nmap(t: str, o: dict) -> list[str]:
    profile = o["profile"]
    args = ["-sT", "-T4", "-Pn", "--max-retries", "1", "--stats-every", "30s"]
    if profile == "quick":
        args.append("-F")
    elif profile == "service":
        args += ["-sV", "--top-ports", "1000"]
    elif profile == "full":
        # min-parallelism is what actually bounds the 65k-port sweep: connect
        # scans serialize behind per-probe timeouts otherwise (benchmark: 2807s
        # with min-rate alone vs 5.6s/1000 ports with parallelism).
        # Trade-off: tight RTT caps can hide ports on very lossy links.
        args += [
            "-p-", "-sV",
            "--min-parallelism", "128", "--max-parallelism", "256",
            "--initial-rtt-timeout", "100ms", "--max-rtt-timeout", "300ms",
        ]
    else:  # vuln
        args += ["-sV", "--script", "vuln"]
    return args + [t]


DNSX_FLAGS = ("-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-resp", "-silent", "-retry", "2")


def _dnsx(t: str, o: dict) -> list[str]:
    return list(DNSX_FLAGS)


def _dnsx_list(path: str, o: dict) -> list[str]:
    return ["-l", path, *DNSX_FLAGS]


HTTPX_FLAGS = (
    "-silent", "-status-code", "-title", "-tech-detect", "-web-server", "-cdn",
    "-ip", "-cname", "-follow-redirects", "-threads", "40", "-timeout", "10",
)


def _httpx(t: str, o: dict) -> list[str]:
    return ["-u", t, *HTTPX_FLAGS]


def _httpx_list(path: str, o: dict) -> list[str]:
    return ["-l", path, *HTTPX_FLAGS]


def _katana_flags(o: dict) -> list[str]:
    return ["-silent", "-d", str(o["depth"]), "-jc", "-kf", "all", "-ct", "5m", "-timeout", "15"]


def _katana(t: str, o: dict) -> list[str]:
    return ["-u", t, *_katana_flags(o)]


def _katana_list(path: str, o: dict) -> list[str]:
    return ["-list", path, *_katana_flags(o)]


def _gau(t: str, o: dict) -> list[str]:
    args = [t, "--threads", "5"]
    if o["subs"]:
        args.append("--subs")
    return args


def _ffuf(t: str, o: dict) -> list[str]:
    url = t.rstrip("/") + "/FUZZ"
    args = [
        "-u", url, "-w", _wordlist(str(o["wordlist"])),
        "-mc", "200,204,301,302,307,401,403,405", "-t", "40", "-s",
    ]
    if o["extensions"]:
        args += ["-e", o["extensions"]]
    return args


def _gobuster(t: str, o: dict) -> list[str]:
    args = [
        "dir", "-u", t.rstrip("/"), "-w", _wordlist(str(o["wordlist"])),
        "-t", "10", "-q", "--no-color",
    ]
    if o["skip_tls"]:
        args.append("-k")
    return args


def _nuclei_flags(o: dict) -> list[str]:
    args = ["-silent", "-severity", o["severity"]]
    if o["tags"]:
        args += ["-tags", o["tags"]]
    return args


def _nuclei(t: str, o: dict) -> list[str]:
    return ["-u", t, *_nuclei_flags(o)]


def _nuclei_list(path: str, o: dict) -> list[str]:
    return ["-l", path, *_nuclei_flags(o)]


def _gowitness(t: str, o: dict) -> list[str]:
    return ["scan", "single", "--url", t, "--screenshot-path", str(SHOTS)]


def _crtsh(t: str, o: dict) -> list[str]:
    return []


def _shodan(t: str, o: dict) -> list[str]:
    return []


def _censys(t: str, o: dict) -> list[str]:
    return []


# ---------------------------------------------------------------- registry


REGISTRY: tuple[Tool, ...] = (
    # ---------------- passive / OSINT
    Tool(
        id="amass",
        name="Amass",
        group="Passive / OSINT",
        blurb="Attack-surface mapping and subdomain discovery.",
        target="domain",
        binary=("amass",),
        passive=True,
        build=_amass,
        options=(
            Opt("mode", "Mode", "select", "passive", ("passive", "active")),
        ),
        note="Passive uses public sources; active adds DNS brute forcing.",
        install="go install -v github.com/owasp-amass/amass/v4/cmd/amass@master",
        docs="https://owasp.org/www-project-amass/",
        timeout=1200,
        version=("-h",),
    ),
    Tool(
        id="theharvester",
        name="theHarvester",
        group="Passive / OSINT",
        blurb="Emails, hosts, subdomains and names from public sources.",
        target="domain",
        binary=("theHarvester", "theharvester"),
        passive=True,
        build=_harvester,
        options=(
            Opt(
                "sources", "Sources", "text",
                "crtsh,otx,urlscan,duckduckgo",
                hint="Comma-separated, or 'all'. Many sources need API keys.",
            ),
            Opt("limit", "Result limit", "text", "300"),
        ),
        note="Default sources work without API keys.",
        install="pipx install theHarvester",
        docs="https://github.com/laramies/theHarvester",
        timeout=900,
        version=("-h",),
    ),
    Tool(
        id="spiderfoot",
        name="SpiderFoot",
        group="Passive / OSINT",
        blurb="Correlates OSINT across 200+ modules.",
        target="host",
        binary=("spiderfoot", "sf.py"),
        passive=True,
        build=_spiderfoot,
        options=(
            Opt("modules", "Modules", "text", "all"),
        ),
        note="Broad and slow. Needs sf.py (or 'spiderfoot') on PATH.",
        install="pipx install spiderfoot",
        docs="https://github.com/smicallef/spiderfoot",
        timeout=1800,
        version=("-h",),
    ),
    Tool(
        id="bbot",
        name="BBOT",
        group="Passive / OSINT",
        blurb="Recursive discovery presets across passive and active sources.",
        target="domain",
        binary=("bbot",),
        build=_bbot,
        options=(
            Opt(
                "preset", "Preset", "select", "subdomain-enum",
                ("subdomain-enum", "web-basic", "email-enum", "spider", "cloud-enum"),
            ),
        ),
        note="On Windows this uses a WSL bridge; on Linux/macOS install normally.",
        install="Windows: WSL Ubuntu + pipx install bbot (bridge at ~/.local/bin/bbot.exe). Linux/macOS: pipx install bbot.",
        docs="https://www.blacklanternsecurity.com/bbot/",
        timeout=1800,
        version=("--version",),
    ),
    # ---------------- network / DNS
    Tool(
        id="nmap",
        name="Nmap",
        group="Network / DNS",
        blurb="Ports, services, versions and NSE scripts.",
        target="host",
        binary=("nmap",),
        build=_nmap,
        options=(
            Opt(
                "profile", "Profile", "select", "quick",
                ("quick", "service", "full", "vuln"),
                hint="quick=top 100 ports, service=top 1000 + versions, full=all ports",
            ),
        ),
        note="Connect scan (-sT) so it runs without root or Npcap privileges.",
        install="winget install -e --id Insecure.Nmap",
        docs="https://nmap.org/book/man.html",
        timeout=1800,
        version=("--version",),
    ),
    Tool(
        id="dnsx",
        name="dnsx",
        group="Network / DNS",
        blurb="Fast DNS resolution: A, AAAA, CNAME, MX, NS, TXT.",
        target="domain",
        binary=("dnsx",),
        build=_dnsx,
        list_build=_dnsx_list,
        passive=True,
        stdin=True,
        note="Reads the target from stdin, like the shell examples.",
        install="go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        docs="https://github.com/projectdiscovery/dnsx",
        timeout=300,
    ),
    # ---------------- web / app
    Tool(
        id="httpx",
        name="httpx",
        group="Web / App",
        blurb="Live host probing: status, title, tech, server, CDN.",
        target="url",
        binary=("httpx",),
        build=_httpx,
        list_build=_httpx_list,
        # The Python httpx package also installs an `httpx` command; it prints
        # "httpx 0.28.1" or a pip hint, while ProjectDiscovery does not.
        version=("--version",),
        match=r"(pip install 'httpx\[cli\]'|^httpx \d+\.\d+\.\d+\s*$)",
        strict_match=True,
        note="ProjectDiscovery httpx (Go), not the Python httpx CLI.",
        install="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        docs="https://github.com/projectdiscovery/httpx",
        timeout=180,
    ),
    Tool(
        id="katana",
        name="Katana",
        group="Web / App",
        blurb="Crawls sites including JavaScript endpoints.",
        target="url",
        binary=("katana",),
        build=_katana,
        list_build=_katana_list,
        options=(
            Opt("depth", "Depth", "select", "3", ("1", "2", "3", "4", "5")),
        ),
        note="JS crawling (-jc) is on; headless mode is off.",
        install="go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
        docs="https://github.com/projectdiscovery/katana",
        timeout=420,
    ),
    Tool(
        id="gau",
        name="gau",
        group="Web / App",
        blurb="Historical URLs from Wayback, Common Crawl and OTX.",
        target="domain",
        binary=("gau",),
        build=_gau,
        passive=True,
        options=(Opt("subs", "Include subdomains", "bool", True),),
        install="go install -v github.com/lc/gau/v2/cmd/gau@latest",
        docs="https://github.com/lc/gau",
        timeout=300,
        version=("--version",),
    ),
    Tool(
        id="ffuf",
        name="ffuf",
        group="Web / App",
        blurb="Content and endpoint fuzzing with a wordlist.",
        target="url",
        binary=("ffuf",),
        build=_ffuf,
        options=(
            Opt("wordlist", "Wordlist", "text", "wordlists/common.txt"),
            Opt("extensions", "Extensions", "text", "", hint="e.g. .php,.bak (optional)"),
        ),
        note="Filters to 200/204/3xx/401/403/405 responses.",
        install="go install -v github.com/ffuf/ffuf/v2@latest",
        docs="https://github.com/ffuf/ffuf",
        timeout=900,
        version=("-V",),
    ),
    Tool(
        id="gobuster",
        name="Gobuster",
        group="Web / App",
        blurb="Directory and file brute forcing.",
        target="url",
        binary=("gobuster",),
        build=_gobuster,
        options=(
            Opt("wordlist", "Wordlist", "text", "wordlists/common.txt"),
            Opt("skip_tls", "Skip TLS verification", "bool", False),
        ),
        install="go install -v github.com/OJ/gobuster/v3@latest",
        docs="https://github.com/OJ/gobuster",
        timeout=900,
        version=("--version",),
    ),
    Tool(
        id="nuclei",
        name="Nuclei",
        group="Web / App",
        blurb="Template checks for exposures, CVEs and misconfigurations.",
        target="url",
        binary=("nuclei",),
        build=_nuclei,
        list_build=_nuclei_list,
        options=(
            Opt(
                "severity", "Severity", "select", "critical,high,medium,low",
                ("critical,high,medium,low", "critical,high", "critical,high,medium"),
            ),
            Opt("tags", "Tags", "text", "", hint="e.g. cve,exposure,panel (optional)"),
        ),
        note="The first run downloads the template repository.",
        install="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        docs="https://docs.projectdiscovery.io/tools/nuclei/overview",
        timeout=1800,
    ),
    Tool(
        id="gowitness",
        name="GoWitness",
        group="Web / App",
        blurb="Screenshots web assets for fast visual triage.",
        target="url",
        binary=("gowitness",),
        build=_gowitness,
        note="v3 syntax. Screenshots land in the Shots tab.",
        install="go install -v github.com/sensepost/gowitness@latest",
        docs="https://github.com/sensepost/gowitness",
        timeout=180,
        version=("version",),
    ),
    # ---------------- external APIs
    Tool(
        id="crtsh",
        name="crt.sh",
        group="External APIs",
        blurb="Certificate transparency history: subdomains and issuers.",
        target="domain",
        passive=True,
        api="crtsh",
        build=_crtsh,
        note="Public, no key. Often busy; retry if it errors.",
        docs="https://crt.sh/",
        timeout=90,
    ),
    Tool(
        id="shodan",
        name="Shodan",
        group="External APIs",
        blurb="Exposed services and DNS data for a host or domain.",
        target="host",
        passive=True,
        api="shodan",
        build=_shodan,
        install="Set SHODAN_API_KEY in .env",
        docs="https://developer.shodan.io/api",
        timeout=60,
    ),
    Tool(
        id="censys",
        name="Censys",
        group="External APIs",
        blurb="Certificate and service search across the internet.",
        target="host",
        passive=True,
        api="censys",
        build=_censys,
        install="Set CENSYS_API_TOKEN (free Platform PAT) in .env",
        docs="https://docs.censys.com/reference/get-started",
        timeout=60,
    ),
)

BY_ID = {tool.id: tool for tool in REGISTRY}
GROUPS = tuple(dict.fromkeys(tool.group for tool in REGISTRY))
EXAMPLES = {"domain": "example.com", "url": "https://example.com", "host": "10.0.0.5"}


def by_id(tool_id: str) -> Tool:
    tool = BY_ID.get(tool_id)
    if not tool:
        raise KeyError(f"Unknown tool: {tool_id}")
    return tool


def defaults(tool: Tool) -> dict[str, Any]:
    return {o.key: o.default for o in tool.options}


def coerce(tool: Tool, incoming: dict[str, Any] | None) -> dict[str, Any]:
    """Validate submitted options against the tool's declared options."""
    incoming = incoming or {}
    values: dict[str, Any] = {}
    for opt in tool.options:
        value = incoming.get(opt.key, opt.default)
        if opt.kind == "bool":
            values[opt.key] = (
                value if isinstance(value, bool)
                else str(value).strip().lower() in ("1", "true", "on", "yes")
            )
        elif opt.kind == "select":
            if value not in opt.choices:
                raise ValueError(f"{opt.label}: choose one of {', '.join(opt.choices)}")
            values[opt.key] = value
        else:
            text = str(value).strip()
            if len(text) > 1000:
                raise ValueError(f"{opt.label} is too long")
            values[opt.key] = text
    return values


def preview(tool: Tool) -> str:
    if tool.api:
        return f"{tool.api.upper()} request -> {EXAMPLES[tool.target]}"
    if not tool.build:
        return ""
    try:
        args = tool.build(EXAMPLES[tool.target], defaults(tool))
    except ValueError as exc:
        return f"(needs config: {exc})"
    return shlex.join([tool.binary[0] if tool.binary else "?", *args])
