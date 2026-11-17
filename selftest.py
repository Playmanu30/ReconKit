"""Assert-based self-check. Run with: python selftest.py

Uses a throwaway SQLite database so it never touches your real scan history.
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time
from pathlib import Path

os.environ["RECON_DB"] = str(
    Path(tempfile.gettempdir()) / f"reconkit-selftest-{os.getpid()}.db"
)

from reconkit import analyze, config, registry, runner, scope, store  # noqa: E402
from reconkit.registry import Tool  # noqa: E402

config.load_env()
for key in ("AI_API_KEY", "OPENAI_API_KEY"):
    os.environ.pop(key, None)  # force the deterministic local analyser

CHECKS = 0


def check(condition: object, message: str) -> None:
    global CHECKS
    assert condition, message
    CHECKS += 1


# ---------------------------------------------------------------- scope
check(scope.normalize("domain", "Example.COM.") == "example.com", "domain lowercase")
check(scope.normalize("domain", "*.example.com") == "example.com", "wildcard strip")
check(scope.normalize("url", "EXAMPLE.com/path/") == "https://example.com/path", "url normalise")
check(scope.normalize("url", "http://example.com:8080/a?b=1") == "http://example.com:8080/a?b=1", "url port+query")
check(scope.normalize("host", "10.0.0.5") == "10.0.0.5", "ip host")
check(scope.normalize("host", "example.com") == "example.com", "domain host")
check(scope.allowed("api.example.com", ["example.com"]), "subdomain allowed")
check(scope.allowed("example.com", ["example.com"]), "root allowed")
check(not scope.allowed("notexample.com", ["example.com"]), "suffix trap rejected")
check(not scope.allowed("example.com.evil.net", ["example.com"]), "suffix attack rejected")
for bad in ("http://", "example", "10.0.0.0/24", "a b.com"):
    try:
        scope.normalize("host", bad)
    except ValueError:
        check(True, f"rejected {bad}")
    else:
        check(False, f"accepted invalid target {bad}")

# ---------------------------------------------------------------- registry
for tool in registry.REGISTRY:
    check(tool.group in registry.GROUPS, f"{tool.id} has a known group")
    if tool.api or not tool.build:
        check(bool(tool.api or tool.build), f"{tool.id} has a runner")
        continue
    args = tool.build(registry.EXAMPLES[tool.target], registry.defaults(tool))
    check(isinstance(args, list), f"{tool.id} builds a list")
    check(all(isinstance(arg, str) for arg in args), f"{tool.id} args are strings")
    check(all("{" not in arg for arg in args), f"{tool.id} has no template leftovers")
    if not tool.stdin:
        check(
            any("example.com" in arg or "10.0.0.5" in arg for arg in args),
            f"{tool.id} passes the target as one argument",
        )

try:
    registry.coerce(registry.by_id("nmap"), {"profile": "bogus"})
except ValueError:
    check(True, "invalid select rejected")
else:
    check(False, "invalid select accepted")

nmap_full = registry.by_id("nmap").build(
    "10.0.0.5", registry.coerce(registry.by_id("nmap"), {"profile": "full"})
)
check("--min-parallelism" in nmap_full, "nmap full profile parallelises connect probes")
check("--max-retries" in nmap_full, "nmap full profile skips retransmit waits")

# ---------------------------------------------------------------- analyser
sample = (
    "Starting Nmap 7.95\n"
    "22/tcp open  ssh     OpenSSH 9.6\n"
    "80/tcp open  http    nginx 1.24\n"
    "[high] CVE-2023-1234 example exposure\n"
)
summary, engine = asyncio.run(
    analyze.analyze(registry.by_id("nmap"), "example.com", sample, "done")
)
check(engine == "rules", "analysis falls back to rules without a key")
check("22/tcp" in summary, "analyser lists open ports")
check("CVE-2023-1234" in summary, "analyser extracts CVEs")

ffuf_out = ".env\nadmin\napi\nbackup.zip\n"
ffuf_summary, _ = asyncio.run(
    analyze.analyze(registry.by_id("ffuf"), "http://127.0.0.1:8000", ffuf_out, "done")
)
check("paths found" in ffuf_summary, "analyser parses ffuf's silent path list")
check(".env" in ffuf_summary, "analyser keeps ffuf findings")

gobuster_out = ".env                 (Status: 200) [Size: 47]\nadmin (Status: 301) [Size: 0]\n"
gobuster_summary, _ = asyncio.run(
    analyze.analyze(registry.by_id("gobuster"), "http://127.0.0.1:8000", gobuster_out, "done")
)
check("admin" in gobuster_summary, "analyser parses gobuster output")

empty_summary, _ = asyncio.run(
    analyze.analyze(registry.by_id("httpx"), "https://example.com", "", "done")
)
check("no output" in empty_summary, "analyser explains a finished scan with empty output")

harvest_opts = registry.coerce(registry.by_id("theharvester"), {})
check("bing" not in harvest_opts["sources"], "theHarvester default sources exclude bing")

nx_summary, _ = asyncio.run(
    analyze.analyze(
        registry.by_id("nmap"),
        "news.vinted.com",
        'Failed to resolve "news.vinted.com".\nWARNING: No targets were specified, so 0 hosts scanned.\n',
        "done",
    )
)
check("does not exist (NXDOMAIN)" in nx_summary, "analyser explains unresolvable targets")

check(scope.resolves("127.0.0.1"), "IP literal counts as resolved")

bbot_out = (
    "[FINDING] Severity: [INFO] Confidence: [HIGH] OAuth endpoint at "
    "https://login.example.com/token\n"
)
bbot_summary, _ = asyncio.run(
    analyze.analyze(registry.by_id("bbot"), "example.com", bbot_out, "done")
)
check("nuclei findings" not in bbot_summary, "BBOT confidence is not a nuclei severity")
check("[FINDING]" in bbot_summary, "BBOT findings are highlighted")

# ---------------------------------------------------------------- handoff
from reconkit import handoff  # noqa: E402

sample_out = (
    "https://api.example.com/x\n"
    "*.dev.example.com\n"
    "https://evil.net/y\n"
    "10.0.0.5\n"
    "mail@example.com\n"
    "example.com\n"
)
found = handoff.extract(sample_out)
urls = handoff.select(found, ["example.com"], "url")
hosts = handoff.select(found, ["example.com"], "domain")
check(any("api.example.com" in url for url in urls), "handoff keeps in-scope URLs")
check(not any("evil.net" in url for url in urls), "handoff drops out-of-scope URLs")
check("dev.example.com" in hosts, "handoff strips certificate wildcards")
check("10.0.0.5" not in hosts, "handoff keeps IPs out of a domain list")
check(any(url.startswith("http://example.com") for url in urls), "handoff adds http for bare hosts")
check(any(url.startswith("https://example.com") for url in urls), "handoff adds https for bare hosts")
check(handoff.select(found, [], "url") == [], "empty scope yields no targets")

for tool_id in ("dnsx", "httpx", "katana", "nuclei"):
    list_tool = registry.by_id(tool_id)
    args = list_tool.list_build("C:/tmp/list.txt", registry.defaults(list_tool))
    check("C:/tmp/list.txt" in args, f"{tool_id} list builder uses the list file")

# ---------------------------------------------------------------- runner
config.ensure_dirs()
store.init()
fake = Tool(
    id="selftest",
    name="SelfTest",
    group="Web / App",
    blurb="",
    target="domain",
    binary=("python",),
    build=lambda target, options: [],
)
job = runner.start_cli(
    fake, "example.com", [sys.executable, "-c", "print('hello recon')"], None, 20
)
deadline = time.time() + 15
while job.status == "running" and time.time() < deadline:
    time.sleep(0.05)
check(job.status == "done", f"job finished (status={job.status}, error={job.error})")
check("hello recon" in job.text(), "job output captured")
row = store.get_scan(job.id)
check(row is not None and "hello recon" in row["output"], "job persisted to sqlite")
runner.JOBS.pop(job.id, None)

# ---------------------------------------------------------------- HTTP API
from fastapi.testclient import TestClient  # noqa: E402

from reconkit.app import app  # noqa: E402

client = TestClient(app)
check(client.get("/api/health").json()["ok"] is True, "health endpoint")
index = client.get("/")
check(index.status_code == 200 and "RECONKIT" in index.text, "console page served")
tools = client.get("/api/tools").json()["tools"]
check(len(tools) >= 15, "tool registry exposed")
check(all("engine" in tool and "options" in tool for tool in tools), "tool payload shape")

blocked = client.post("/api/scans", json={"tool_id": "nmap", "target": "example.org"})
check(blocked.status_code == 403, "out-of-scope target blocked")
check(blocked.json()["detail"]["code"] == "out_of_scope", "block carries a reason")

added = client.post("/api/scope", json={"root": "example.org"}).json()
check("example.org" in added["roots"], "scope add works")
removed = client.delete("/api/scope/example.org").json()
check("example.org" not in removed["roots"], "scope remove works")
check(client.get("/api/shots").status_code == 200, "screenshots endpoint")

store.save_scan(
    {
        "id": "handoff-test",
        "tool": "httpx",
        "tool_name": "httpx",
        "target": "http://example.com",
        "status": "done",
        "started": time.time() - 5,
        "finished": time.time(),
        "exit_code": 0,
        "argv": [],
        "output": "https://api.example.com/x [200]\nhttps://evil.net/y [200]\n",
        "analysis": "",
        "engine": "",
    }
)
client.post("/api/scope", json={"root": "example.com"})
handoff_payload = client.get("/api/scans/handoff-test/handoff")
check(handoff_payload.status_code == 200, "handoff endpoint responds")
preview = " ".join(handoff_payload.json()["preview"])
check(handoff_payload.json()["count"] >= 1, "handoff endpoint counts in-scope targets")
check("api.example.com" in preview, "handoff preview includes in-scope host")
check("evil.net" not in preview, "handoff preview excludes out-of-scope host")

print(f"selftest: {CHECKS} checks passed")

for suffix in ("", "-wal", "-shm"):
    path = Path(str(config.DB_PATH) + suffix)
    try:
        if path.exists():
            path.unlink()
    except PermissionError:
        pass
