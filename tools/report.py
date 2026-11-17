"""Build one Markdown assessment report from stored ReconKit scans.

Examples:
  python tools/report.py --since "2026-11-16 19:20" --out docs/assessment-report.md
  python tools/report.py --target example.com --out report.md
"""

from __future__ import annotations

import argparse
import shlex
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from reconkit import __version__, config, store  # noqa: E402

MAX_OUTPUT = 8000


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a Markdown report from stored scans.")
    parser.add_argument("--target", help="Only include targets containing this text.")
    parser.add_argument(
        "--since",
        help='Only include scans started at/after local time, e.g. "2026-11-16 19:20".',
    )
    parser.add_argument("--out", default=str(ROOT / "docs" / "assessment-report.md"))
    parser.add_argument("--limit", type=int, default=200)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not config.DB_PATH.is_file():
        raise SystemExit(f"No scan database at {config.DB_PATH}. Run a scan first.")

    since = None
    if args.since:
        try:
            since = datetime.fromisoformat(args.since).timestamp()
        except ValueError:
            raise SystemExit(
                '--since must look like 2026-11-16 or "2026-11-16 19:20"'
            ) from None

    selected = []
    for summary in store.list_scans(limit=args.limit):
        if args.target and args.target not in summary["target"]:
            continue
        if since and summary["started"] < since:
            continue
        scan = store.get_scan(summary["id"])
        if scan:
            selected.append(scan)
    selected.sort(key=lambda scan: scan["started"])

    lines = [
        "# ReconKit — Assessment Report",
        "",
        f"- Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"- ReconKit: {__version__}",
        f"- Scope: {', '.join(store.scope_roots()) or 'none'}",
        f"- Runs: {len(selected)}",
    ]
    if args.target:
        lines.append(f"- Target filter: {args.target}")
    if args.since:
        lines.append(f"- Since: {args.since}")
    lines += [
        "",
        "> Passive API lookups (Shodan, Censys, crt.sh) do not send traffic to the",
        "> target. Active scans were limited to the Scope list above.",
        "> Review this file before sharing; raw output may contain sensitive data.",
        "",
    ]

    if not selected:
        lines.append("_No scans matched the filter._")
    else:
        lines += [
            "## Run summary",
            "",
            "| # | Started | Tool | Target | Status | Duration | Exit |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
        for index, scan in enumerate(selected, 1):
            started = datetime.fromtimestamp(scan["started"]).strftime("%Y-%m-%d %H:%M:%S")
            duration = round((scan.get("finished") or scan["started"]) - scan["started"], 1)
            exit_code = "" if scan.get("exit_code") is None else str(scan["exit_code"])
            lines.append(
                f"| {index} | {started} | {scan['tool_name']} | `{scan['target']}` | "
                f"{scan['status']} | {duration}s | {exit_code} |"
            )

        lines += ["", "## Runs", ""]
        for index, scan in enumerate(selected, 1):
            argv = scan.get("argv") or []
            lines += [
                f"### {index}. {scan['tool_name']} — {scan['target']}",
                "",
                f"- Status: **{scan['status']}**"
                + (f" (exit {scan['exit_code']})" if scan.get("exit_code") is not None else ""),
                f"- Duration: {round((scan.get('finished') or scan['started']) - scan['started'], 1)}s",
            ]
            if argv:
                lines.append(f"- Command: `{shlex.join(argv)}`")
            lines.append("")

            output = scan.get("output") or ""
            if output:
                lines += ["```text", output[:MAX_OUTPUT].rstrip(), "```"]
                if len(output) > MAX_OUTPUT:
                    lines.append(f"\n_Output truncated at {MAX_OUTPUT} characters._")
            else:
                lines.append("_No output._")

            if scan.get("analysis"):
                label = "AI" if scan.get("engine") == "ai" else "Rules"
                lines += ["", f"**Analysis ({label})**", "", scan["analysis"]]
            lines.append("")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {out_path} ({len(selected)} runs)")


if __name__ == "__main__":
    main()
