# Evidence — local smoke test

Date: 2026-11-16
Operator: local workstation
Target: `http://127.0.0.1:8081` — an isolated lab fixture on the same machine
(`index.html`, `robots.txt`, `.env`, `admin/`, `api/status.json`, `backup.zip`).

The BBOT bridge validation used `example.com`, a reserved documentation domain,
with the passive `subdomain-enum` preset; its temporary scope entry was removed.
A light real-target demo used `scanme.nmap.org`, the Nmap project's public test
host: only a quick Nmap scan, DNS resolution, one HTTP probe and crt.sh were run.
No other third-party host was scanned.

## Environment

| Component | Version |
| --- | --- |
| Python (app venv) | 3.14.8 |
| FastAPI / Uvicorn | 0.163.1 / 0.54.0 |
| Go | 1.27.4 |
| Nmap | 7.80 |
| Amass | 4.2.0 |
| theHarvester | 5.0.0 |
| SpiderFoot | 4.0.0 |
| BBOT | 3.1.0 (WSL 2 Ubuntu 24.04 bridge) |
| httpx | 1.12.0 |
| dnsx | 1.3.1 |
| Katana | 1.8.0 |
| Nuclei | 3.11.1 (templates updated) |
| gau | 2.2.4 |
| ffuf | 2.1.0-dev |
| Gobuster | 3.8.2 |
| GoWitness | 3.2.2 |
| Ollama (local AI) | 0.40.16 · `qwen2.5:3b` (8B installed but VRAM-bound on 8 GB) |
| Wordlists | SecLists `common.txt` (4,752) and `raft-medium-directories.txt` (29,999) |

## Engine status

16/16 engines ready. Shodan and Censys credentials are configured. BBOT is
bridged into WSL (Ubuntu 24.04, Redis, BBOT 3.1.0).

## BBOT bridge

Windows has no native BBOT, so the app drives an imported Ubuntu 24.04.5 WSL2
distro (official base rootfs; no Store or admin required):

- Python 3.12, pipx, Redis 7.0.15, BBOT 3.1.0.
- A Go shim at `~/.local/bin/bbot.exe` forwards argv to
  `/usr/local/bin/bbot` and starts Redis if needed.
- `bbot -t example.com -p subdomain-enum -y --no-color`: completed in **120.8 s**.
  Results: 2 subdomains, 5 Wayback URLs, 15 social URLs, 4 IPs, 4 HTTP responses.
  BBOT saved outputs under `/root/.bbot/scans/wheedling_peggy/`.
- The app's local `qwen2.5:3b` model summarized the run in **5.6 s**; the raw
  output remains the evidence.

## Real-target demo (scanme.nmap.org)

A light, authorised validation against Nmap's public test host:

| Step | Result |
| --- | --- |
| Nmap `quick` | 22/tcp ssh, 80/tcp http open; 20.3 s |
| dnsx | A `45.33.32.156`, AAAA `2600:3c01::f03c:91ff:fe18:bb2f` |
| httpx (HTTPS) | no response; a single TCP connect to 443 failed from this workstation (unconfirmed, needs a second vantage point) |
| httpx (HTTP) | 200, title `Go ahead and ScanMe!`, `Apache/2.4.7 (Ubuntu)` |
| crt.sh | no certificate for `scanme.nmap.org` |
| ffuf `common.txt` (4,752 words, `-rate 50`) | 101.5 s, 10 paths responded: `.hta`, `.htpasswd`, `.htaccess`, `.svn`, `.svn/entries`, `favicon.ico`, `images`, `index`, `index.html`, `shared` |
| Nuclei (`tags=apache`, sev `critical,high,medium`) | 28.8 s, **0 template matches** |

Scans were sized to the Nmap project's request that the box not be scanned
heavily: quick port scan, DNS, one HTTP probe, a public CT lookup, one
rate-capped 4,752-word directory check and an Apache-tagged Nuclei subset.
No crawling or full-template exploit sweep was run against the public host;
the 30k-word `raft-medium` fuzz and the full Nuclei run went to the isolated
local lab instead (`admin`/`api` variants in 169 s; no findings). The temporary
scope entry was removed after each session. The generated report is
[`scanme-report.md`](scanme-report.md).

Apache 2.4.7 is an old banner. NVD returns **138 CVEs** for the exact 2.4.7 CPE
(**23 high/critical** under CVSS v3, e.g. CVE-2021-44224, CVE-2016-5387,
CVE-2017-15715), and the Apache-tagged Nuclei check matched nothing. Both are
version-based leads, not validated findings: Ubuntu backports fixes into old
version numbers, the banner can be masked, and many CVEs need modules or
configurations a banner cannot reveal. The local model flagged the open
SSH/HTTP services but did not infer a CVE from the version alone. The AI summary
of the empty Nuclei run also echoed a local `CENSYS_API_TOKEN` warning as if
it were a finding — a model artifact; the raw output is the evidence.

## API checks

| Source | Target | Result |
| --- | --- | --- |
| Shodan | `1.1.1.1` | 200; 16 ports, hostnames, org `APNIC Research and Development` |
| Shodan | `example.com` | 200; DNS subdomains and A/AAAA records |
| Censys | `1.1.1.1` | 200; host record, ASN 13335, services including DNS/HTTP/HTTPS |
| Censys | domain | resolves A/AAAA first; the free PAT uses host lookup (global search is org-gated) and the app retries 429s (one active request on the free tier) |

## Results

| Step | Tool | Result |
| --- | --- | --- |
| 1 | Nmap `quick` | 135/tcp msrpc, 445/tcp microsoft-ds, 8081/tcp open on localhost (7.4 s) |
| 2 | httpx | `http://127.0.0.1:8081` → 200, title `ReconKit local lab`, `SimpleHTTP/0.6 Python/3.14.8` |
| 3 | Katana | `/`, `/api/`, `/admin/`, `/api/status.json` |
| 4 | ffuf (`common.txt`, 4,752 words) | `.env`, `ADMIN`, `Admin`, `admin`, `api`, `index.html`, `nul`, `robots.txt` — 24.3 s |
| 5 | Gobuster (`common.txt`) | `.env`, `ADMIN`, `Admin`, `admin`, `api`, `index.html`, `nul`, `robots.txt` — 2.1 s |
| 6 | GoWitness | screenshot of `127.0.0.1:8081` (200, title `ReconKit local lab`); visible in the Shots tab |
| 7 | Nuclei | template repository cloned (14,557 files); no findings on a static lab (info severity excluded) |
| 8 | ffuf `raft-medium-directories.txt` (29,999 words, `-rate 200`) | 6 hits: `admin`, `Admin`, `ADMIN`, `api`, `API`, `Api`; 169 s. The list is directory-focused, so no files were expected. |

## Handoff chain

1. **httpx → Katana** — 1 in-scope URL extracted. The Katana argv used
   `-list data/lists/<id>.txt`; the list contained only
   `http://127.0.0.1:8081`. Katana returned 4 URLs.
2. **Katana → Nuclei** — 4 in-scope URLs extracted (UI showed
   `4 in scope`, target line `Nuclei → http://127.0.0.1:8081 · 4 inputs`).
3. Out-of-scope filtering is covered by the automated test: an
   `https://evil.net/y` line in a source output never reaches the list.

The UI reports per-tool counts because dnsx consumes hostnames (1) while
URL-capable tools consume the four URLs.

## Analysis output

### Rules fallback

Without an AI key/model, the deterministic summariser produced:

```
RULE-BASED SUMMARY - ffuf - http://127.0.0.1:8081
Status: done    Output: 8 lines

WHAT IT FOUND
- 8 paths found: .env, ADMIN, Admin, admin, api, index.html, nul, robots.txt
```

### Local AI (Ollama qwen2.5:3b)

With the local model, the same scan produced in **2.1 s**:

```
FINDINGS:
- Directory: .env
- Directory: / (implied from .env)
- Directory: /api
- Directory: /admin
- Directory: /index.html
- Directory: /nul
- Directory: /robots.txt

RISK: No risk is evidenced by this run.

NEXT:
- Verify if the .env file contains sensitive information.
- Check if the /admin directory requires authentication.
- Investigate if the /nul directory is accessible and if it could be used for unintended purposes.
```

The 3B model is small enough to leave VRAM for the desktop. It still mislabels
files as directories and understates the exposed `.env`; the raw output is the
evidence, not the summary. `llama3.1:8b` is installed too, but it thrashes an
8 GB GPU alongside the desktop (~2 tok/s), so it is not the default.

Two findings require manual validation before they belong in a report:

- `/nul` is a Windows device name, not evidence of a file.
- The three `admin` case variants are the same resource on this filesystem.

## Screenshots

- `screenshots/console.png` — first-run console.
- `screenshots/setup.png` - engine detection (16 ready).
- `screenshots/bbot.png` - BBOT 3.1.0 running through the WSL bridge.
- `screenshots/api.png` — live Censys host lookup from the app.
- `screenshots/ai.png` — local AI analysis (`AI · qwen2.5:3b`).
- `screenshots/results.png` — a completed scan with the rules fallback.
- `screenshots/handoff.png` — the handoff control with in-scope counts.
- `screenshots/shots.png` — GoWitness output in the Shots tab.

## Automated checks

`python selftest.py` → **120 checks passed**, covering:

- target normalisation and scope-suffix traps;
- every tool's argument builder and list builder;
- ffuf/Gobuster/nmap/Nuclei analysis parsing;
- handoff extraction, scope filtering and wildcard/IP handling;
- a real subprocess job, persistence and the HTTP API;
- the out-of-scope gate and the handoff endpoint.

## Reproduction

The lab is documented in the README ("Local lab without Docker"). Start it on a
free port, add `127.0.0.1` to Scope, then repeat steps 2–6. Use
**Hand off in-scope targets** on the httpx run to reproduce the chain.

A generated report for the ffuf run is in [`sample-report.md`](sample-report.md).
A consolidated multi-run report is in
[`assessment-report.md`](assessment-report.md) (11 runs: the final local lab plus
the Shodan/Censys validation).
