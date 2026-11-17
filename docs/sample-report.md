# ReconKit scan - ffuf

- Target: `http://127.0.0.1:8081`
- Tool: `ffuf`
- Status: done (exit 0)
- Started: 2026-11-16 19:25:52
- Duration: 24.3s

## Command

```
C:\Users\crims\go\bin\ffuf.EXE -u http://127.0.0.1:8081/FUZZ -w E:\Opencode\Project toolkit\project2\wordlists\common.txt -mc 200,204,301,302,307,401,403,405 -t 40 -s
```

## Output

```
.env
ADMIN
Admin
admin
api
index.html
nul
robots.txt

```

## Analysis

RULE-BASED SUMMARY - ffuf - http://127.0.0.1:8081
Status: done    Output: 8 lines

WHAT IT FOUND
- 8 paths found: .env, ADMIN, Admin, admin, api, index.html, nul, robots.txt

NEXT STEPS
- Inspect every 200/401/403 finding manually; confirm nothing is a soft-404 before reporting.
- Validate every finding manually: recon output contains false positives.
- Record the asset, evidence and timestamp before writing any report.
