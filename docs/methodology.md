# ReconKit — Assessment Methodology

This document describes the workflow ReconKit supports for an authorised
external reconnaissance assessment. It is written for coursework and lab use,
not as a substitute for a signed scope agreement.

## 1. Objective

Map the external attack surface of an authorised target and keep every step
reproducible: what was scanned, with which flags, what came back, how it was
interpreted, and which asset it belongs to.

## 2. Scope and authorisation

- Every active CLI engine is gated on an entry in the **Scope** allowlist. The
  gate is enforced in the backend, not only in the browser.
- A scoped root also authorises its subdomains. `example.com` does **not**
  authorise `notexample.com` or `example.com.evil.net`; CIDR ranges are rejected
  by design.
- Only the third-party APIs (`crt.sh`, Shodan, Censys) skip the gate because
  they read public data and send nothing to the target.
- **Handoff** lists are filtered against the same scope before they are written
  to disk. A source scan cannot smuggle an out-of-scope host into the next
  phase.
- The server binds to `127.0.0.1` and has no authentication. It is a
  single-operator workstation tool; do not expose the port.
- Tools run as an argument list (`subprocess.Popen(argv)`), never through a
  shell. Extra flags are split with `shlex` and remain arguments, so shell
  metacharacters are not interpreted.

## 3. Workflow

### Phase 1 — Passive OSINT and attack-surface mapping

1. **crt.sh** — certificate-transparency history. Cheap, public, often gives
   the first subdomain list.
2. **Amass** (`enum -d <domain> -passive`) — public-source mapping. Switch the
   Mode option to `active` to add DNS brute forcing.
3. **theHarvester** — emails, hosts, employee names. The default source list
   (`crtsh,otx,urlscan,duckduckgo,bing`) works without API keys.
4. **SpiderFoot** — broad module correlation. Slow; use it when breadth matters.
5. **BBOT** - recursive presets (`subdomain-enum`, `web-basic`, `email-enum`,
   `spider`, `cloud-enum`). On Windows it runs through the WSL bridge (Ubuntu
   24.04 + Redis + the `bbot.exe` shim); Linux/macOS run it natively.
6. **gau** — historical URLs from Wayback, Common Crawl and OTX.

Save the output of this phase as the candidate asset list. Do not assume a
hostname is live until it resolves and responds.

### Phase 2 — Network and service validation

1. **dnsx** — resolve A/AAAA/CNAME/MX/NS/TXT at speed.
2. **Nmap**:
   - `quick` → top 100 ports, connect scan.
   - `service` → top 1000 ports + version detection.
   - `full` → all ports + version detection (slow).
   - `vuln` → version detection + the `vuln` NSE category.

Nmap runs as `-sT` (connect scan) so it works without root or Npcap. Record the
exact profile in the report.

### Phase 3 — Web and application enumeration

1. **httpx** — filter live HTTP(S) hosts, status, title, technologies, server,
   CDN, IP and CNAME.
2. **Katana** — crawl, including JavaScript endpoints (`-jc`).
3. **gau** — add archived endpoints that no longer appear in the crawl.
4. **ffuf / Gobuster** — directory and file discovery with a wordlist.
   The default is SecLists `common.txt` (4,752 entries); `raft-medium-directories.txt`
   (29,999 entries) is available for deeper runs.
5. **Nuclei** — template checks for exposures, CVEs and misconfigurations. The
   first run clones the template repository; later runs are fast.
6. **GoWitness** — screenshots for visual triage. Images appear in the **Shots**
   tab.

### Phase 4 — Handoff

A finished scan can be handed to the next list-capable engine directly:

| Source | Typical next step |
| --- | --- |
| crt.sh / Amass / theHarvester / BBOT | dnsx → httpx |
| httpx | Katana, Nuclei |
| Katana / gau | Nuclei |
| Nmap | httpx (adds `http://` and `https://` for bare hosts) |

Only in-scope hosts and URLs are written to the list. The UI shows the exact
per-tool target count before you run it. Lists are stored in `data/lists/`.

## 4. Evidence handling

Each run stores: id, tool, target, status, exit code, start/finish timestamps,
the exact argv, full output (capped at 2 MB), and the analysis text in
`data/reconkit.db`. **Export .md** produces a self-contained report with the
command, raw output and analysis. Screenshots are kept under
`data/screenshots/` and served from the Shots tab.

Recommended evidence order:

1. Raw output and argv (exported Markdown).
2. Screenshot or HTTP response for anything you intend to report.
3. Manual validation note (what you tried, what confirmed it).
4. Timestamp and target asset.

## 5. Analysis layer

- With the shipped `.env`, **Ollama (`qwen2.5:3b`) runs locally**. Analysis stays
  on this host, takes a couple of seconds when warm, and still works offline.
- With an OpenAI-compatible cloud key, output goes to that provider instead.
- Without either, a deterministic local summariser extracts open ports, paths,
  URLs, emails, CVEs, nuclei severities and tool-specific next steps. No network
  request is made.
- The model is an assistant, not an oracle. It is instructed not to invent
  assets or vulnerabilities, and every claim must be checked against the raw
  output before it reaches a report. Small local models can still mislabel data.
- Scan output can contain sensitive data. With cloud AI configured, that output
  leaves your machine. The shipped configuration uses local Ollama only.

## 6. False positives and validation

Recon output is a lead, not a finding. Check at least:

- **Soft 404s and custom error pages** — a 200 response is not proof of a file.
  Compare response sizes and bodies; ffuf/Gobuster only report size/status.
- **Windows device names** — `nul`, `con`, `aux` can appear in a scan because
  the local HTTP server treats them specially. In the sample run, `/nul` is such
  an artefact, not a real file.
- **Case variants** — `ADMIN`, `Admin` and `admin` can all be hits on a
  case-insensitive filesystem, or separate resources on a case-sensitive one.
- **Nuclei info templates** — the default severity filter excludes `info`, so an
  empty run is not proof that nothing exists.
- **Historical URLs** — gau entries may be dead. Re-request them before
  reporting.
- **Certificates** — crt.sh names include wildcard and expired certificates;
  verify the host resolves and serves the expected service.

## 7. Limitations

- Shodan and Censys use the operator's accounts and quotas. A free Censys token
  supports host lookup only; global search needs a paid organization ID.
- SpiderFoot and BBOT are Python-version/platform sensitive in this build (see
  the README's engine notes); they are installed separately from the app venv.
  BBOT runs through the WSL bridge on Windows; the bridge needs the imported
  Ubuntu distro, Redis and the `bbot.exe` shim. Linux/macOS run it natively.
- Handoff is one hop at a time and intentionally manual. There is no scheduler,
  distributed scanning, multi-user auth or PDF report generator.
- Tool flags drift between versions. The Setup panel probes versions and shows
  conflicts, but a major upgrade can still change output formats.

## 8. Ethics and legal

Only scan systems you own or have explicit written permission to test. Add a
target to Scope only when that is true; the checkbox is a record of your
decision, not a grant of permission. Public data APIs (crt.sh, Shodan, Censys)
still have terms of service. Do not use this toolkit to harass, bypass access
controls, or scan third parties opportunistically.
