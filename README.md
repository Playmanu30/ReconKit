# ReconKit

A local recon console for authorised security testing. One interface for the
tools you already know, with live output, one-click handoff between phases,
scan history, screenshots, an AI summary layer, and a hard authorisation gate.

Built for a cyber-security student's lab work: every run is recorded, every
finding can be turned into a short report, and nothing is sent anywhere unless
you configure it.

```
Passive / OSINT   amass · theHarvester · SpiderFoot · BBOT
Network / DNS     nmap · dnsx
Web / App         httpx · katana · gau · ffuf · gobuster · nuclei · gowitness
External APIs     crt.sh · Shodan · Censys
```

## Why this exists

Running the tools is the easy part. The hard part is keeping the thread:
which target was scanned with which flags, where the output went, what the
result actually means, and whether you were allowed to scan it. ReconKit keeps
all of that in one place and never loses the raw output.

## Quick start

Requires Python 3.10+.

**Windows**

```bat
run.bat
```

The launcher creates `.venv`, installs the three Python dependencies, starts the
server on `http://127.0.0.1:8777`, and opens your browser.

**Manual (any OS)**

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate      Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python -m reconkit
```

Optional checks and overrides:

```bash
python selftest.py        # 120 assertions, uses a throwaway database
# RECON_PORT=9000 python -m reconkit
# RECON_NO_BROWSER=1 python -m reconkit
```

## Install the engines

ReconKit orchestrates tools installed on your machine; it does not bundle them.
Open **Setup** in the app to see what was detected and copy install commands.
Typical Windows setup:

| Engine | Install |
| --- | --- |
| Go toolchain (for the ProjectDiscovery tools) | `winget install GoLang.Go` |
| Nmap | `winget install -e --id Insecure.Nmap` |
| Amass | `go install -v github.com/owasp-amass/amass/v4/cmd/amass@master` |
| dnsx | `go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| httpx | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| Katana | `go install -v github.com/projectdiscovery/katana/cmd/katana@latest` |
| gau | `go install -v github.com/lc/gau/v2/cmd/gau@latest` |
| ffuf | `go install -v github.com/ffuf/ffuf/v2@latest` |
| Gobuster | `go install -v github.com/OJ/gobuster/v3@latest` |
| Nuclei | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| GoWitness | `go install -v github.com/sensepost/gowitness@latest` |
| theHarvester | `pipx install "git+https://github.com/laramies/theHarvester.git"` (current master needs Python 3.14) |
| SpiderFoot | source checkout + Python 3.12 venv + console launcher (see below) |
| BBOT | Windows: WSL bridge (Ubuntu + `tools/bbot_shim.go`). Linux/macOS: `pipx install bbot`. |

Go binaries land in `%USERPROFILE%\go\bin` on Windows and `~/go/bin` elsewhere.
`pipx` apps land in `%USERPROFILE%\.local\bin`. ReconKit searches `~/go/bin`,
`~/.local/bin` and its own venv scripts first, so these tools are found without
changing your shell PATH. Restart the app and click **Setup → refresh**.

### Heavy Python engines

BBOT is Unix-only (`fcntl`/`resource`). On Windows, ReconKit runs it through a
WSL bridge: an imported Ubuntu 24.04 rootfs, `pipx install bbot`, Redis, and a
small Go shim at `~/.local/bin/bbot.exe` that forwards the app's argv into WSL.
The shim starts Redis if it is not running. This workstation is already wired;
to reproduce it:

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\WSL\Ubuntu" | Out-Null
curl.exe -L -o "$env:TEMP\ubuntu.tar.gz" "https://cdimage.ubuntu.com/ubuntu-base/releases/24.04/release/ubuntu-base-24.04.5-base-amd64.tar.gz"
wsl --import Ubuntu "$env:USERPROFILE\WSL\Ubuntu" "$env:TEMP\ubuntu.tar.gz" --version 2
wsl -d Ubuntu -u root -- bash -c "apt-get update && apt-get install -y python3-pip pipx redis-server git curl ca-certificates"
wsl -d Ubuntu -u root -- bash -c "PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install bbot"
go build -o "$env:USERPROFILE\.local\bin\bbot.exe" tools\bbot_shim.go
```

Linux/macOS can run BBOT natively with `pipx install bbot`.

SpiderFoot's repository has no `setup.py`/`pyproject.toml`, so it cannot be
installed with `pipx install spiderfoot`. Run it from a source checkout:

```powershell
winget install --id Python.Python.3.12 -e --scope user
git clone --depth 1 https://github.com/smicallef/spiderfoot "$env:USERPROFILE\tools\spiderfoot"
cd "$env:USERPROFILE\tools\spiderfoot"
py -3.12 -m venv venv
.\venv\Scripts\pip install -r requirements.txt
```

Then expose `sf.py` through a real `.exe` console launcher (this workstation
uses a pipx-installed shim) and set `RECON_SPIDERFOOT` if it is not on PATH.
A `.cmd` shim is not enough: ReconKit never routes argv through a shell, and
Windows cannot execute a `.cmd` directly with `Popen`.

Some calls out:

- **httpx name collision.** The Python `httpx` library also installs an `httpx`
  command. ReconKit probes the binary and shows *wrong binary* instead of letting
  you run an argparse error. It also puts `~/go/bin` and `~/.local/bin` first for
  its own process, so the ProjectDiscovery build wins after a restart.
- **Nmap connect scans.** The app uses `-sT`, so it works without root or Npcap.
  That is slower than a SYN scan but portable.
- **Nuclei templates** are updated on this machine already; on a fresh install
  they clone on first run. Behind a proxy, set `HTTP_PROXY`/`HTTPS_PROXY`.
- **theHarvester / BBOT / SpiderFoot** are Python-version sensitive. The
  theHarvester master branch currently requires Python 3.14; BBOT is Unix-only
  (bridged through WSL on Windows); SpiderFoot is not pip-installable from its
  repo.

## Keys and the AI layer

```bash
copy .env.example .env
```

- `SHODAN_API_KEY` — enables the Shodan tool (host lookup and DNS data).
- `CENSYS_API_TOKEN` — a Censys Platform Personal Access Token. The free tier
  supports host lookup; the global search endpoint requires an organization ID
  from a paid plan. Legacy `CENSYS_API_ID`/`CENSYS_API_SECRET` still work too.
- `AI_API_KEY` + `AI_BASE_URL` + `AI_MODEL` — any OpenAI-compatible endpoint.
  With no key, analysis uses a deterministic local summariser (ports, URLs,
  emails, CVEs, nuclei severities, next steps).
- With the shipped `.env`, **Ollama runs locally** (`qwen2.5:3b`), so analysis
  stays on this machine. Switch to a cloud provider only if you accept sending
  scan output there.

Both Shodan and Censys have free account tiers. Credentials are read from `.env`
and never sent to the browser. The current `.env` has the keys configured; for a
different account replace them and restart the app.

Ollama setup on a new machine:

```powershell
winget install Ollama.Ollama
ollama pull qwen2.5:3b
```

Then set:

```ini
AI_BASE_URL=http://127.0.0.1:11434/v1
AI_API_KEY=ollama
AI_MODEL=qwen2.5:3b
```

On an 8 GB GPU the 3B model leaves VRAM headroom and runs interactively.
`llama3.1:8b` is also installed but thrashes an 8 GB card alongside the desktop
(~2 tok/s); use it only if you have spare VRAM.

When a cloud endpoint is configured, clicking **Analyse** sends that scan's
output to the provider. With the local Ollama endpoint it never leaves the
machine. There is no telemetry.

## The authorisation gate

This is the part reviewers ask about, so it is enforced in the backend, not the UI.

1. Before an active scan, the target must be added to **Scope** with an explicit
   acknowledgement that you own it or have written permission.
2. A scoped root also authorises its subdomains. `example.com` does not authorise
   `notexample.com`, and CIDR ranges are rejected on purpose.
3. Only the third-party APIs (crt.sh, Shodan, Censys) are exempt, because they
   read public data and send no traffic to the target. Every local CLI tool is
   gated, including "passive" ones.
4. Tools run as an argument list (`subprocess.Popen(argv)`), never through a
   shell. The Extra flags box is split with `shlex` into separate arguments, so
   `; rm -rf /` is a scan flag, not a command.
5. The server binds to `127.0.0.1` only and has no authentication. Do not expose
   the port or run it on a shared host as-is.

Scope and history live in `data/reconkit.db`. Delete the file to reset.

## A sane first session

1. Start the app, open **Setup**, install one or two engines (start with Nmap and
   httpx), refresh.
2. Open **Scope**, add a target you are allowed to test. For a first smoke test,
   `scanme.nmap.org` is provided by the Nmap project for light scans. For web
   tools use a local lab (OWASP Juice Shop, DVWA) or an authorised CTF box.
3. Run Nmap (quick profile) on the target. Watch the live output.
4. Click **Analyse**, then **Export .md** for your notes.
5. Move to the web phase: httpx on the URL, then katana/gau, then ffuf or
   nuclei on what looks interesting.
6. On a completed run, use **Hand off in-scope targets** to feed the hosts/URLs
   into the next engine (for example httpx → Katana → Nuclei).

### Local lab without Docker

If you do not have a target of your own yet, serve a throwaway site locally on a
free port (8081 here — 8000 is commonly occupied):

```powershell
New-Item -ItemType Directory -Force lab, lab\admin | Out-Null
Set-Content lab\index.html '<h1>ReconKit lab</h1>'
Set-Content lab\.env 'DEMO_ONLY=1'
Set-Content lab\admin\index.html '<h1>Admin</h1>'
cd lab; python -m http.server 8081 --bind 127.0.0.1
```

Then add `127.0.0.1` to Scope in ReconKit and use
`http://127.0.0.1:8081` as the target. ffuf/Gobuster should find `.env`,
`admin/` and the other files you create. This exercises the whole live-output,
history, analysis and screenshot path without touching anyone else's system.

## Handoff between phases

A finished scan can feed the next list-capable engine without copy-paste:

- **crt.sh / Amass / theHarvester → dnsx → httpx**
- **httpx → Katana or Nuclei**
- **Katana / gau → Nuclei**
- **Nmap → httpx** (bare hosts get both `http://` and `https://`)

Open a completed run and use **Hand off in-scope targets** in the Report panel.
It shows the per-tool target count and a preview before you run anything. Every
entry is re-checked against Scope, so an out-of-scope host in a tool's output
never reaches the next command. Lists are written to `data/lists/`.

Handoff is one hop at a time and deliberately visible; there is no hidden
scheduler or background pipeline.

## What each wrapper runs

| Tool | Default invocation (abridged) |
| --- | --- |
| Amass | `amass enum -d <domain> -passive` |
| theHarvester | `theHarvester -d <domain> -b crtsh,otx,urlscan,duckduckgo,bing -l 300` |
| SpiderFoot | `spiderfoot -s <target> -t DOMAIN_NAME -m all` |
| BBOT | `bbot -t <domain> -p subdomain-enum -y --no-color` |
| Nmap | `nmap -sT -T4 -Pn -F <host>` |
| dnsx | `dnsx -a -aaaa -cname -mx -ns -txt -resp -silent` (target on stdin) |
| httpx | `httpx -u <url> -silent -status-code -title -tech-detect -web-server -cdn -ip -cname -follow-redirects` |
| Katana | `katana -u <url> -silent -d 3 -jc -kf all -ct 5m` |
| gau | `gau <domain> --threads 5 --subs` |
| ffuf | `ffuf -u <url>/FUZZ -w wordlists/common.txt -mc 200,204,301,302,307,401,403,405 -s` |
| Gobuster | `gobuster dir -u <url> -w wordlists/common.txt -t 10 -q --no-color` |
| Nuclei | `nuclei -u <url> -silent -severity critical,high,medium,low` |
| GoWitness | `gowitness scan single --url <url> --screenshot-path data/screenshots` |
| crt.sh | `GET https://crt.sh/?q=%.<domain>&output=json` |
| Shodan | host lookup for an IP, DNS domain lookup for a domain |
| Censys | host lookup for an IP; a domain is resolved to A/AAAA addresses first |

Every tool also has an **Extra flags** field appended to the command, so the
wrapper is a starting point, not a cage.

`dnsx`, `httpx`, Katana and Nuclei also support a target-list file; the handoff
UI uses it. dnsx consumes hostnames while the web tools consume URLs.

The bundled wordlists are from [SecLists](https://github.com/danielmiessler/SecLists)
(MIT): `common.txt` (4,752 entries) is the default for ffuf/Gobuster, and
`raft-medium-directories.txt` (29,999) is available for deeper runs. Point the
Wordlist option at either path, or at your own SecLists checkout.

## Adding an engine

One entry in `reconkit/registry.py`, no other file:

```python
Tool(
    id="assetfinder",
    name="Assetfinder",
    group="Passive / OSINT",
    blurb="Related domains and subdomains.",
    target="domain",
    binary=("assetfinder",),
    passive=True,
    build=lambda target, options: ["--subs-only", target],
    install="go install github.com/tomnomnom/assetfinder@latest",
    docs="https://github.com/tomnomnom/assetfinder",
)
```

Options are declared (`Opt(...)`) and validated server-side. Raw user input only
reaches argv through the Extra flags field.

## Project layout

```
reconkit/
  app.py        FastAPI routes, SSE stream, export, handoff endpoint
  registry.py   tool definitions, exact flags, list builders
  runner.py     process jobs, live output, cancel/timeout, persistence
  engines.py    binary discovery and version probes
  scope.py      target normalisation and the authorisation allowlist
  handoff.py    output extraction, scope filtering, target lists
  analyze.py    LLM client + rule-based fallback
  external.py   crt.sh, Shodan, Censys clients
  store.py      SQLite scans and scope
web/            the console (vanilla HTML/CSS/JS, no build step)
wordlists/      SecLists common + raft-medium
docs/           methodology, evidence, combined report, sample report, screenshots
tools/          report.py + bbot_shim.go (WSL bridge)
selftest.py     assert-based checks for the core paths
```

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `httpx` shows *wrong binary* | The Python httpx CLI is on PATH. Install ProjectDiscovery httpx, set `RECON_HTTPX`, or let the app's `~/go/bin` preference win after a restart. |
| Go tools not detected | Add `%USERPROFILE%\go\bin` (Windows) or `~/go/bin` to PATH, restart. The app also searches it directly. |
| theHarvester not detected | Current master needs Python 3.14. `pipx install "git+https://github.com/laramies/theHarvester.git"`. |
| SpiderFoot not detected | It needs a source checkout and a real `.exe` console launcher; see *Heavy Python engines*. |
| BBOT not detected / bridge fails | Check `wsl -d Ubuntu -u root -- /usr/local/bin/bbot --version`; the Windows shim is `~/.local/bin/bbot.exe`. The shim starts Redis. |
| `nmap` asks for root | Not here: the wrapper uses `-sT`. If you added `-sS` yourself, that is on you. |
| crt.sh returns 502 / non-JSON | It is frequently overloaded. Retry, or use Shodan/Censys. |
| Nuclei finds nothing | Check that templates exist (`nuclei -update-templates`); info-severity findings are filtered out by default. |
| `Address already in use` | `RECON_PORT=9000 python -m reconkit`. |
| Dependency changes ignored | The launcher uses `.venv\.deps-installed` as a marker; delete `.venv` to rebuild. |
| Windows Defender flags ffuf/nuclei | Common false positive for Go security tools. Verify the download source, then allow that file. Do not disable Defender globally. |

## Deliberately not included (v1)

- **Maltego** — commercial desktop GUI with no CLI to orchestrate. SpiderFoot plus
  the markdown export covers correlation for this use case.
- **EyeWitness** — its workflow is GUI-oriented; GoWitness provides screenshots
  and the Shots tab.
- **Scheduled or continuous scanning, remote agents** — every run is started by
  the operator and is visible in the history.
- **Multi-user auth, remote access, PDF reports** — this is a single-user
  localhost tool. `Export .md` is enough for notes; use pandoc for a PDF.
- **CIDR / mass scanning** — the scope model is host and subdomain based.

## Docs

- [`docs/methodology.md`](docs/methodology.md) — scope model, phase workflow,
  evidence handling, false-positive checks, limitations.
- [`docs/evidence.md`](docs/evidence.md) — installed versions, local smoke-test
  results, handoff chain and screenshots.
- [`docs/sample-report.md`](docs/sample-report.md) — a generated report from a
  real ffuf run.
- [`docs/assessment-report.md`](docs/assessment-report.md) — one combined report
  from the final local-lab and API runs.
- [`docs/scanme-report.md`](docs/scanme-report.md) — a light, authorised
  real-target demo against `scanme.nmap.org` (Nmap quick, dnsx, HTTP probe,
  crt.sh only; no fuzzing).

To build a report from your own stored runs:

```powershell
python tools/report.py --target example.com
python tools/report.py --since "2026-11-16 19:20" --out docs/my-report.md
```

## Legal

Use ReconKit only against systems you own or have explicit written permission to
test. Unauthorised scanning is illegal in most jurisdictions and is not a
"research" exemption. The scope gate exists so your authorisation decisions are
explicit and auditable — not as a substitute for actually having authorisation.
