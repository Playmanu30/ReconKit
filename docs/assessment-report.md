# ReconKit — Assessment Report

- Generated: 2026-11-16 22:13
- ReconKit: 1.1.0
- Scope: 127.0.0.1
- Runs: 11
- Since: 2026-11-16 19:20

> Passive API lookups (Shodan, Censys, crt.sh) do not send traffic to the
> target. Active scans were limited to the Scope list above.
> Review this file before sharing; raw output may contain sensitive data.

## Run summary

| # | Started | Tool | Target | Status | Duration | Exit |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 2026-11-16 19:22:34 | httpx | `http://127.0.0.1:8081` | done | 0.9s | 0 |
| 2 | 2026-11-16 19:22:49 | Katana | `http://127.0.0.1:8081` | done | 17.7s | 0 |
| 3 | 2026-11-16 19:25:52 | ffuf | `http://127.0.0.1:8081` | done | 24.3s | 0 |
| 4 | 2026-11-16 19:30:32 | Nmap | `127.0.0.1` | done | 7.4s | 0 |
| 5 | 2026-11-16 19:30:32 | Gobuster | `http://127.0.0.1:8081` | done | 2.1s | 0 |
| 6 | 2026-11-16 19:30:32 | GoWitness | `http://127.0.0.1:8081` | done | 4.9s | 0 |
| 7 | 2026-11-16 21:19:11 | Shodan | `1.1.1.1` | done | 0.2s |  |
| 8 | 2026-11-16 21:19:11 | Shodan | `example.com` | done | 0.1s |  |
| 9 | 2026-11-16 21:19:11 | Censys | `1.1.1.1` | error | 1.1s |  |
| 10 | 2026-11-16 21:19:11 | Censys | `example.com` | done | 1.8s |  |
| 11 | 2026-11-16 21:20:15 | Censys | `1.1.1.1` | done | 2.1s |  |

## Runs

### 1. httpx — http://127.0.0.1:8081

- Status: **done** (exit 0)
- Duration: 0.9s
- Command: `'C:\Users\crims\go\bin\httpx.EXE' -u http://127.0.0.1:8081 -silent -status-code -title -tech-detect -web-server -cdn -ip -cname -follow-redirects -threads 40 -timeout 10`

```text
http://127.0.0.1:8081 [200] [ReconKit local lab] [SimpleHTTP/0.6 Python/3.14.8] [127.0.0.1] [Python:3.14.8,SimpleHTTP:0.6]
```

### 2. Katana — http://127.0.0.1:8081

- Status: **done** (exit 0)
- Duration: 17.7s
- Command: `'C:\Users\crims\go\bin\katana.EXE' -list 'E:\Opencode\Project toolkit\project2\data\lists\38a26088620540b79c4e62eaf6a3ba21.txt' -silent -d 3 -jc -kf all -ct 5m -timeout 15`

```text
http://127.0.0.1:8081
http://127.0.0.1:8081/api/
http://127.0.0.1:8081/admin/
http://127.0.0.1:8081/api/status.json
```

**Analysis (Rules)**

RULE-BASED SUMMARY - Katana - http://127.0.0.1:8081
Status: done    Output: 4 lines

WHAT IT FOUND
- 4 unique URLs, e.g. http://127.0.0.1:8081, http://127.0.0.1:8081/admin/, http://127.0.0.1:8081/api/, http://127.0.0.1:8081/api/status.json

NEXT STEPS
- Filter interesting paths, then fuzz parameters and check for exposed panels or APIs.
- Validate every finding manually: recon output contains false positives.
- Record the asset, evidence and timestamp before writing any report.

### 3. ffuf — http://127.0.0.1:8081

- Status: **done** (exit 0)
- Duration: 24.3s
- Command: `'C:\Users\crims\go\bin\ffuf.EXE' -u http://127.0.0.1:8081/FUZZ -w 'E:\Opencode\Project toolkit\project2\wordlists\common.txt' -mc 200,204,301,302,307,401,403,405 -t 40 -s`

```text
.env
ADMIN
Admin
admin
api
index.html
nul
robots.txt
```

**Analysis (AI)**

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

### 4. Nmap — 127.0.0.1

- Status: **done** (exit 0)
- Duration: 7.4s
- Command: `'C:\Program Files (x86)\Nmap\nmap.EXE' -sT -T4 -Pn -F 127.0.0.1`

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2026-11-16 19:30 India Standard Time
Nmap scan report for 127.0.0.1
Host is up (0.00s latency).
Not shown: 97 filtered ports
PORT     STATE SERVICE
135/tcp  open  msrpc
445/tcp  open  microsoft-ds
8081/tcp open  blackice-icecap

Nmap done: 1 IP address (1 host up) scanned in 7.37 seconds
```

### 5. Gobuster — http://127.0.0.1:8081

- Status: **done** (exit 0)
- Duration: 2.1s
- Command: `'C:\Users\crims\go\bin\gobuster.EXE' dir -u http://127.0.0.1:8081 -w 'E:\Opencode\Project toolkit\project2\wordlists\common.txt' -t 10 -q --no-color`

```text
.env                 (Status: 200) [Size: 47]
ADMIN                (Status: 301) [Size: 0] [--> /ADMIN/]
Admin                (Status: 301) [Size: 0] [--> /Admin/]
admin                (Status: 301) [Size: 0] [--> /admin/]
api                  (Status: 301) [Size: 0] [--> /api/]
index.html           (Status: 200) [Size: 290]
nul                  (Status: 200) [Size: 0]
robots.txt           (Status: 200) [Size: 31]
```

### 6. GoWitness — http://127.0.0.1:8081

- Status: **done** (exit 0)
- Duration: 4.9s
- Command: `'C:\Users\crims\go\bin\gowitness.EXE' scan single --url http://127.0.0.1:8081 --screenshot-path 'E:\Opencode\Project toolkit\project2\data\screenshots'`

```text
2026/11/16 19:30:33 WARN no writers have been configured. to persist probe results, add writers using --write-* flags
2026/11/16 19:30:37 INFO result 🤖 target=http://127.0.0.1:8081 status-code=200 title="ReconKit local lab" have-screenshot=true
```

### 7. Shodan — 1.1.1.1

- Status: **done**
- Duration: 0.2s

```text
Shodan - host 1.1.1.1
Org: APNIC Research and Development   ISP: Cloudflare, Inc.
ASN: AS13335   OS: -
Country: Australia   Last update: 2026-11-16T10:49:51.162782
Open ports: 161, 2082, 2083, 2052, 69, 2086, 2087, 2095, 80, 8880, 8080, 53, 8443, 443, 2096, 2053
Hostnames: wifi.rklcpa.com, webauth.geron.com, one.one.one.one
Tags: pqc
Known vulns: none reported
------------------------------------------------------------------------
53/tcp                                                        
53/udp                                                        
69/udp   TFTP                                                 
80/tcp                                                        DNS resolution error | webauth.geron.com
161/udp   ciscoSystems                                         
443/tcp   CloudFlare                                           403 Forbidden
2052/tcp                                                        301 Moved Permanently
2053/tcp                                                        1.1.1.1 — The free app that makes your I
2082/tcp                                                        301 Moved Permanently
2083/tcp                                                        1.1.1.1 — The free app that makes your I
2086/tcp                                                        301 Moved Permanently
2087/tcp                                                        1.1.1.1 — The free app that makes your I
2095/tcp                                                        301 Moved Permanently
2096/tcp                                                        1.1.1.1 — The free app that makes your I
8080/tcp   CloudFlare                                           301 Moved Permanently
8443/tcp                                                        1.1.1.1 — The free app that makes your I
8880/tcp   CloudFlare                                           301 Moved Permanently
```

### 8. Shodan — example.com

- Status: **done**
- Duration: 0.1s

```text
Shodan - DNS for example.com
Tags: dmarc, ipv6, spf
Subdomains (3):
  _dmarc.example.com
  k2._domainkey.example.com
  www.example.com
------------------------------------------------------------------------
A      @                            104.20.23.154
A      @                            172.66.147.243
AAAA   @                            2606:4700:10::6814:179a
AAAA   @                            2606:4700:10::ac42:93f3
MX     @                            
NS     @                            elliott.ns.cloudflare.com
NS     @                            hera.ns.cloudflare.com
SOA    @                            elliott.ns.cloudflare.com
TXT    @                            _k2n1y4vw3qtb4skdx9e7dxt97qrmmq9
TXT    @                            v=spf1 -all
TXT    _dmarc                       v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s
TXT    k2._domainkey                v=DKIM1; p=
A      www                          104.20.23.154
A      www                          172.66.147.243
AAAA   www                          2606:4700:10::6814:179a
AAAA   www                          2606:4700:10::ac42:93f3
```

### 9. Censys — 1.1.1.1

- Status: **error**
- Duration: 1.1s

```text
[reconkit] Censys 429: {"title":"Too Many Requests","status":429,"detail":"too many active requests"}
```

### 10. Censys — example.com

- Status: **done**
- Duration: 1.8s

```text
Censys - host data for example.com
Resolved: 172.66.147.243, 104.20.23.154
------------------------------------------------------------------------

IP: 172.66.147.243
Location: United States / San Francisco
ASN: AS13335 CLOUDFLARENET - Cloudflare, Inc.
Services (13):
  80/tcp  HTTP             cloudflare cloudflare_load_balancer      
  443/tcp  HTTP             cloudflare cloudflare_load_balancer      
  2052/tcp  HTTP             cloudflare cloudflare_load_balancer      
  2053/tcp  HTTP             cloudflare cloudflare_load_balancer      
  2082/tcp  HTTP             cloudflare cloudflare_load_balancer      
  2083/tcp  HTTP             cloudflare cloudflare_load_balancer      
  2086/tcp  HTTP             cloudflare cloudflare_load_balancer      
  2087/tcp  HTTP             cloudflare cloudflare_load_balancer      
  2095/tcp  HTTP             cloudflare cloudflare_load_balancer      
  2096/tcp  HTTP             cloudflare cloudflare_load_balancer      
  8080/tcp  HTTP             cloudflare cloudflare_load_balancer      
  8443/tcp  HTTP             cloudflare cloudflare_load_balancer      
  8880/tcp  HTTP             cloudflare cloudflare_load_balancer      

IP: 104.20.23.154
Location: United States / San Francisco
ASN: AS13335 CLOUDFLARENET - Cloudflare, Inc.
Services (13):
  80/tcp  HTTP             cloudflare cloudflare_load_balancer      
  443/tcp  HTTP             cloudflare cloudflare_load_balancer      
  2052/tcp  HTTP             cloudflare cloudflare_load_balancer      
  2053/tcp  HTTP             cloudflare cloudflare_load_balancer      
  2082/tcp  HTTP             cloudflare cloudflare_load_balancer      
  2083/tcp  HTTP             cloudflare cloudflare_load_balancer      
  2086/tcp  HTTP             cloudflare cloudflare_load_balancer      
  2087/tcp  HTTP             cloudflare cloudflare_load_balancer      
  2095/tcp  HTTP             cloudflare cloudflare_load_balancer      
  2096/tcp  HTTP             cloudflare cloudflare_load_balancer      
  8080/tcp  HTTP             cloudflare cloudflare_load_balancer      
  8443/tcp  HTTP             cloudflare cloudflare_load_balancer      
  8880/tcp  HTTP             cloudflare cloudflare_load_balancer
```

### 11. Censys — 1.1.1.1

- Status: **done**
- Duration: 2.1s

```text
Censys - host data for 1.1.1.1
Resolved: 1.1.1.1
------------------------------------------------------------------------

IP: 1.1.1.1
Location: Australia / Brisbane
ASN: AS13335 CLOUDFLARENET - Cloudflare, Inc.
Services (14):
  53/tcp  DNS                                                       
  53/udp  DNS                                                       
  80/tcp  HTTP             cloudflare cloudflare_load_balancer      
  443/tcp  HTTP             cloudflare cloudflare_load_balancer      
  443/quic UNKNOWN                                                   
  853/tcp  DNS                                                       
  2052/tcp  HTTP             cloudflare cloudflare_load_balancer      
  2053/tcp  HTTP             cloudflare cloudflare_load_balancer      
  2082/tcp  HTTP             cloudflare cloudflare_load_balancer      
  2086/tcp  HTTP             cloudflare cloudflare_load_balancer      
  2095/tcp  HTTP             cloudflare cloudflare_load_balancer      
  8080/tcp  HTTP             cloudflare cloudflare_load_balancer      
  8443/tcp  HTTP             cloudflare cloudflare_load_balancer      
  8880/tcp  HTTP             cloudflare cloudflare_load_balancer
```

