# ReconKit — Assessment Report

- Generated: 2026-11-16 23:07
- ReconKit: 1.1.0
- Scope: 127.0.0.1, scanme.nmap.org
- Runs: 5
- Target filter: scanme.nmap.org

> Passive API lookups (Shodan, Censys, crt.sh) do not send traffic to the
> target. Active scans were limited to the Scope list above.
> Review this file before sharing; raw output may contain sensitive data.

## Run summary

| # | Started | Tool | Target | Status | Duration | Exit |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 2026-11-16 23:06:39 | Nmap | `scanme.nmap.org` | done | 20.3s | 0 |
| 2 | 2026-11-16 23:06:39 | dnsx | `scanme.nmap.org` | done | 2.0s | 0 |
| 3 | 2026-11-16 23:06:39 | httpx | `https://scanme.nmap.org` | done | 10.9s | 0 |
| 4 | 2026-11-16 23:06:39 | crt.sh | `scanme.nmap.org` | done | 12.9s |  |
| 5 | 2026-11-16 23:07:28 | httpx | `http://scanme.nmap.org` | done | 11.4s | 0 |

## Runs

### 1. Nmap — scanme.nmap.org

- Status: **done** (exit 0)
- Duration: 20.3s
- Command: `'C:\Program Files (x86)\Nmap\nmap.EXE' -sT -T4 -Pn -F scanme.nmap.org`

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2026-11-16 23:06 India Standard Time
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.22s latency).
Not shown: 98 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 20.29 seconds
```

**Analysis (AI)**

FINDINGS:
- Port 22/tcp open ssh: Exposes a secure shell service.
- Port 80/tcp open http: Exposes a web server.

RISK: 
- Port 22/tcp open ssh: Exposes a secure shell service, which could be exploited if the service is misconfigured or the password is weak.

NEXT:
- Verify if the SSH service is configured with a strong password.
- Check if the web server on port 80 is secure and not exposing sensitive information.
- Ensure that the firewall rules are correctly configured to restrict access to these services.

### 2. dnsx — scanme.nmap.org

- Status: **done** (exit 0)
- Duration: 2.0s
- Command: `'C:\Users\crims\go\bin\dnsx.EXE' -a -aaaa -cname -mx -ns -txt -resp -silent -retry 2`

```text
scanme.nmap.org [A] [45.33.32.156] 
scanme.nmap.org [AAAA] [2600:3c01::f03c:91ff:fe18:bb2f]
```

### 3. httpx — https://scanme.nmap.org

- Status: **done** (exit 0)
- Duration: 10.9s
- Command: `'C:\Users\crims\go\bin\httpx.EXE' -u https://scanme.nmap.org -silent -status-code -title -tech-detect -web-server -cdn -ip -cname -follow-redirects -threads 40 -timeout 10`

_No output._

### 4. crt.sh — scanme.nmap.org

- Status: **done**
- Duration: 12.9s

```text
crt.sh - certificate transparency
Domain: scanme.nmap.org
Certificates: 0   Unique names: 0
------------------------------------------------------------------------
```

### 5. httpx — http://scanme.nmap.org

- Status: **done** (exit 0)
- Duration: 11.4s
- Command: `'C:\Users\crims\go\bin\httpx.EXE' -u http://scanme.nmap.org -silent -status-code -title -tech-detect -web-server -cdn -ip -cname -follow-redirects -threads 40 -timeout 10`

```text
http://scanme.nmap.org [200] [Go ahead and ScanMe!] [Apache/2.4.7 (Ubuntu)] [45.33.32.156] [Apache HTTP Server:2.4.7,Ubuntu]
```

**Analysis (AI)**

FINDINGS:
- Apache HTTP Server running on port 80 of http://scanme.nmap.org

RISK: No risk is evidenced by this run.

NEXT:
- Verify if the server is configured with any known vulnerabilities.
- Check for any misconfigurations that could expose the server to attacks.
- Perform a version update check for Apache HTTP Server.


## Passive CVE leads (Apache 2.4.7)

NVD returns **138 CVEs** for the exact Apache HTTP Server 2.4.7 CPE. The eight
highest-scoring are below. This is **version-based inference only**: Ubuntu may
backport fixes, the banner may be masked, and many CVEs require specific modules
or configurations. No exploit or aggressive scan was run against this host.

| CVE | CVSS | Published | Description |
| --- | --- | --- | --- |
| CVE-2022-23943 | 9.8 | 03/14/2022 | Out-of-bounds Write vulnerability in mod_sed of Apache HTTP Server allows an attacker to overwrite heap memory with p... |
| CVE-2018-1312 | 9.8 | 03/26/2018 | In Apache httpd 2.2.0 to 2.4.29, when generating an HTTP Digest authentication challenge, the nonce sent to prevent r... |
| CVE-2021-26691 | 9.8 | 06/10/2021 | In Apache HTTP Server versions 2.4.0 to 2.4.46 a specially crafted SessionHeader sent by an origin server could cause... |
| CVE-2021-39275 | 9.8 | 09/16/2021 | ap_escape_quotes() may write beyond the end of a buffer when given malicious input. No included modules pass untruste... |
| CVE-2021-44790 | 9.8 | 12/20/2021 | A carefully crafted request body can cause a buffer overflow in the mod_lua multipart parser (r:parsebody() called fr... |
| CVE-2022-22720 | 9.8 | 03/14/2022 | Apache HTTP Server 2.4.52 and earlier fails to close inbound connection when errors are encountered discarding the re... |
| CVE-2022-31813 | 9.8 | 06/09/2022 | Apache HTTP Server 2.4.53 and earlier may not send the X-Forwarded-* headers to the origin server based on client sid... |
| CVE-2017-7679 | 9.8 | 06/20/2017 | In Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26, mod_mime can read one byte past the end of a buffer when... |

CVE details: <https://nvd.nist.gov/vuln/search/results?cpeVersion=2.4.7&query=apache%20http%20server>

## HTTPS confirmation

A single TCP connection to scanme.nmap.org:443 failed from this workstation;
port 80 succeeded. Nmap quick did not test 443 (98 ports were filtered), so this
is one connect attempt, not a port survey. The HTTPS probe returned nothing, which
is consistent with no listener, a firewall, or a path issue. Treat it as
unconfirmed; it needs manual verification from another network before any claim.

## Light active web scan (rate-capped)

Two light, authorised active checks were run against `http://scanme.nmap.org`,
sized to respect the Nmap project's request not to scan the box heavily:

| Run | Result |
| --- | --- |
| ffuf, SecLists `common.txt` (4,752 words, `-rate 50`) | 101.5 s, 10 paths responded |
| Nuclei, `tags=apache`, severity `critical,high,medium` | 28.8 s, **0 template matches** |

ffuf paths: `.hta`, `.htpasswd`, `.htaccess`, `.svn`, `.svn/entries`,
`favicon.ico`, `images`, `index`, `index.html`, `shared`. The engine filters to
200/204/3xx/401/403/405, and Apache returns 403 for `.ht*` by default, so these
are **leads, not confirmed exposures** — each needs a manual status-code check
before it is written up. The local AI analysis for the Nuclei run surfaced a
`CENSYS_API_TOKEN`/`CENSYS_ORGANIZATION_ID` warning instead of the empty result;
that is a local environment-configuration message, not a finding about the
target.

**CVE inference outcome:** the active Apache-tagged Nuclei check found nothing,
and the passive NVD query for `cpe:2.3:a:apache:http_server:2.4.7` returns
**23 high/critical CVEs under CVSS v3** (of 138 total, e.g. CVE-2021-44224,
CVE-2016-5387, CVE-2017-15715). Both directions together still do not confirm a
vulnerability: the version string can be masked, Ubuntu backports fixes into
old version numbers, and many CVEs need specific modules or configurations
(mod_proxy, mod_lua, `<FilesMatch>` expressions) that a banner cannot reveal.
The remaining step is manual: check the actual Ubuntu package revision on the
host against `ubuntu.com/security` before reporting any CVE.

## Scope for the public host

The Nmap project provides scanme.nmap.org for testing and asks that it not be
scanned heavily. Everything in this report was sized accordingly: Nmap quick,
DNS, one HTTP probe, crt.sh, a rate-capped 4,752-word directory check and an
Apache-tagged Nuclei subset (~29 s). The 30k-word `raft-medium` fuzz and the
full Nuclei template set were run only against the isolated local lab.
