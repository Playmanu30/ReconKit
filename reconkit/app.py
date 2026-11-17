"""FastAPI app: serves the console and the JSON/SSE API on localhost."""

from __future__ import annotations

import asyncio
import json
import shlex
import time
from typing import Any
from urllib.parse import quote

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import (
    __version__, analyze, config, engines, external, handoff, registry, runner, scope, store,
)

config.load_env()
config.ensure_dirs()
config.prefer_local_bins()
store.init()

app = FastAPI(title="ReconKit", version=__version__, docs_url=None, redoc_url=None)


class ScanIn(BaseModel):
    tool_id: str
    target: str = ""
    options: dict[str, Any] = {}
    extra_args: str = ""
    source_id: str | None = None


class ScopeIn(BaseModel):
    root: str


def fail(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code, "message": message})


def _tool_payload(tool: registry.Tool, engine: dict) -> dict:
    return {
        "id": tool.id,
        "name": tool.name,
        "group": tool.group,
        "blurb": tool.blurb,
        "target": tool.target,
        "passive": tool.passive,
        "api": tool.api,
        "install": tool.install,
        "docs": tool.docs,
        "note": tool.note,
        "timeout": tool.timeout,
        "preview": registry.preview(tool),
        "options": [
            {
                "key": o.key,
                "label": o.label,
                "kind": o.kind,
                "default": o.default,
                "choices": list(o.choices),
                "hint": o.hint,
            }
            for o in tool.options
        ],
        "engine": engine,
    }


def _scan_payload(scan_id: str) -> dict:
    job = runner.JOBS.get(scan_id)
    if job:
        data = runner.public(job)
        data["output"] = job.text()
        row = store.get_scan(scan_id)
        data["analysis"] = row["analysis"] if row else ""
        data["engine"] = row["engine"] if row else ""
        return data

    row = store.get_scan(scan_id)
    if not row:
        raise fail(404, "not_found", "No such scan.")
    finished = row.get("finished") or row["started"]
    row["duration"] = round(finished - row["started"], 1)
    row["error"] = ""
    return row


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(config.WEB / "index.html")


@app.get("/api/health")
async def health() -> dict:
    return {
        "ok": True,
        "version": __version__,
        "ai": bool(config.setting("AI_API_KEY", "OPENAI_API_KEY")),
        "running": sum(1 for j in runner.JOBS.values() if j.status == "running"),
    }


@app.get("/api/tools")
async def tools() -> dict:
    statuses = engines.check_all(registry.REGISTRY)
    payload = [_tool_payload(tool, statuses[tool.id]) for tool in registry.REGISTRY]
    return {
        "tools": payload,
        "groups": list(registry.GROUPS),
        "ready": sum(1 for s in statuses.values() if s["status"] == "ready"),
        "total": len(payload),
        "ai": {
            "enabled": bool(config.setting("AI_API_KEY", "OPENAI_API_KEY")),
            "model": config.setting("AI_MODEL", default="gpt-4o-mini"),
            "local": "127.0.0.1" in config.setting(
                "AI_BASE_URL", default="https://api.openai.com/v1"
            ) or "localhost" in config.setting(
                "AI_BASE_URL", default="https://api.openai.com/v1"
            ),
        },
    }


@app.get("/api/engines")
async def engine_status(refresh: int = 0) -> dict:
    return engines.check_all(registry.REGISTRY, refresh=bool(refresh))


@app.get("/api/scope")
async def get_scope() -> dict:
    return {"roots": store.scope_roots()}


@app.post("/api/scope")
async def add_scope(body: ScopeIn) -> dict:
    try:
        root = scope.normalize("host", body.root)
    except ValueError as exc:
        raise fail(400, "invalid_target", str(exc)) from None
    store.scope_add(root)
    return {"roots": store.scope_roots(), "added": root}


@app.delete("/api/scope/{root}")
async def remove_scope(root: str) -> dict:
    store.scope_remove(root.lower().rstrip("."))
    return {"roots": store.scope_roots()}


@app.post("/api/scans")
async def start_scan(body: ScanIn) -> dict:
    try:
        tool = registry.by_id(body.tool_id)
    except KeyError as exc:
        raise fail(404, "unknown_tool", str(exc)) from None

    source = None
    if body.source_id:
        source = store.get_scan(body.source_id)
        if not source:
            raise fail(404, "unknown_source", "That source scan does not exist.")
        if source["status"] == "running":
            raise fail(409, "source_running", "Wait for the source scan to finish.")
        if not tool.list_build:
            raise fail(400, "not_handoff", f"{tool.name} cannot take a target list.")
        target = (body.target or "").strip() or source["target"]
    else:
        try:
            target = scope.normalize(tool.target, body.target)
        except ValueError as exc:
            raise fail(400, "invalid_target", str(exc)) from None

    # A handoff list is filtered against the scope before it is written, so its
    # metadata label is not a security boundary. Direct scans are gated here.
    if not tool.api and not source and not scope.allowed(scope.host_of(target), store.scope_roots()):
        raise fail(
            403,
            "out_of_scope",
            f"{scope.host_of(target)} is not in scope. Add it only if you own it "
            "or have written permission to test it.",
        )

    # Fail fast on typos and dead domains instead of running a scan whose only
    # output is the tool's resolver warning. Passive tools are exempt: OSINT
    # databases can hold history for domains that no longer resolve.
    if (
        not tool.api
        and not tool.passive
        and not source
        and tool.target != "domain"
        and not await asyncio.to_thread(scope.resolves, scope.host_of(target))
    ):
        raise fail(
            400,
            "unresolved",
            f"{scope.host_of(target)} does not exist in DNS. Check the spelling, "
            "or enter an IP address.",
        )

    if sum(1 for j in runner.JOBS.values() if j.status == "running") >= 6:
        raise fail(429, "too_many_jobs", "Six scans are already running. Wait for one to finish.")

    if tool.api:
        return runner.public(
            runner.start_api(tool, target, lambda: external.run(tool, target))
        )

    binary = engines.resolve(tool)
    if not binary:
        raise fail(400, "not_installed", f"{tool.name} is not installed. {tool.install}")
    state = engines.check(tool)
    if state["status"] == "unsupported":
        raise fail(400, "unsupported", state["message"])
    if state["status"] == "conflict":
        raise fail(400, "wrong_binary", state["message"])

    extra: list[str] = []
    if body.extra_args.strip():
        if len(body.extra_args) > 500:
            raise fail(400, "invalid_option", "Extra flags are limited to 500 characters.")
        try:
            extra = shlex.split(body.extra_args)[:40]
        except ValueError:
            raise fail(400, "invalid_option", "Extra flags contain an unbalanced quote.") from None

    list_path = None
    input_count = 0
    try:
        values = registry.coerce(tool, body.options)
        if source:
            kind = "domain" if tool.target == "domain" else "url"
            targets = handoff.select(
                handoff.extract(source["output"]), store.scope_roots(), kind
            )
            if not targets:
                raise fail(
                    400,
                    "no_targets",
                    "No in-scope targets were found in that scan. Add the host to "
                    "Scope only if you are authorised to test it.",
                )
            list_path = handoff.write_list(targets)
            input_count = len(targets)
            tail = tool.list_build(str(list_path), values) if tool.list_build else []
        else:
            tail = tool.build(target, values) if tool.build else []
    except ValueError as exc:
        if list_path:
            list_path.unlink(missing_ok=True)
        raise fail(400, "invalid_option", str(exc)) from None

    argv = [binary, *tail, *extra]
    stdin_data = f"{target}\n" if tool.stdin and not source else None
    job = runner.start_cli(tool, target, argv, stdin_data, tool.timeout, input_count)
    return runner.public(job)


@app.get("/api/scans")
async def list_scans() -> dict:
    return {"scans": store.list_scans()}


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str) -> dict:
    return _scan_payload(scan_id)


@app.get("/api/scans/{scan_id}/handoff")
async def scan_handoff(scan_id: str) -> dict:
    job = runner.JOBS.get(scan_id)
    if job and job.status == "running":
        raise fail(409, "running", "Wait for the scan to finish.")
    row = store.get_scan(scan_id)
    if not row:
        raise fail(404, "not_found", "No such scan.")

    data = handoff.extract(row["output"])
    roots = store.scope_roots()
    url_targets = handoff.select(data, roots, "url")
    host_targets = handoff.select(data, roots, "domain")

    candidates = []
    for tool in registry.REGISTRY:
        if not tool.list_build:
            continue
        if engines.check(tool)["status"] != "ready":
            continue
        count = len(host_targets if tool.target == "domain" else url_targets)
        if count:
            candidates.append({"id": tool.id, "name": tool.name, "count": count})

    return {
        "count": max(len(url_targets), len(host_targets)),
        "urls": len(url_targets),
        "hosts": len(host_targets),
        "preview": (url_targets or host_targets)[:12],
        "tools": candidates,
    }


@app.post("/api/scans/{scan_id}/stop")
async def stop_scan(scan_id: str) -> dict:
    job = runner.JOBS.get(scan_id)
    if not job:
        raise fail(404, "not_found", "No such running scan.")
    if not runner.cancel(job):
        raise fail(409, "not_running", "This scan already finished.")
    return runner.public(job)


@app.get("/api/scans/{scan_id}/stream")
async def stream_scan(scan_id: str, request: Request) -> StreamingResponse:
    if scan_id not in runner.JOBS and not store.get_scan(scan_id):
        raise fail(404, "not_found", "No such scan.")

    def event(name: str, data: dict) -> str:
        return f"event: {name}\ndata: {json.dumps(data)}\n\n"

    async def generate():
        position = 0
        last_ping = time.monotonic()
        while True:
            job = runner.JOBS.get(scan_id)
            if job is None:
                row = store.get_scan(scan_id)
                if row and row["output"]:
                    yield event("chunk", {"v": row["output"]})
                yield event(
                    "end",
                    {"status": row["status"] if row else "missing", "exit_code": None},
                )
                return

            while position < len(job.output):
                end = min(position + 40, len(job.output))
                yield event("chunk", {"v": "".join(job.output[position:end])})
                position = end

            if job.status != "running":
                yield event(
                    "end",
                    {"status": job.status, "exit_code": job.exit_code, "error": job.error},
                )
                return

            if time.monotonic() - last_ping > 15:
                yield ": ping\n\n"
                last_ping = time.monotonic()
            await asyncio.sleep(0.15)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/scans/{scan_id}/analyze")
async def analyze_scan(scan_id: str) -> dict:
    row = store.get_scan(scan_id)
    job = runner.JOBS.get(scan_id)
    if not row and not job:
        raise fail(404, "not_found", "No such scan.")
    if job and job.status == "running":
        raise fail(409, "running", "Wait for the scan to finish before analysing.")

    source = row or {}
    tool = registry.BY_ID.get(source.get("tool") or (job.tool if job else ""))
    output = (job.text() if job else "") or source.get("output") or ""
    target = source.get("target") or (job.target if job else "")
    status = source.get("status") or (job.status if job else "")

    text, engine = await analyze.analyze(tool, target, output, status)
    store.set_analysis(scan_id, text, engine)
    return {"analysis": text, "engine": engine}


@app.get("/api/scans/{scan_id}/export")
async def export_scan(scan_id: str) -> PlainTextResponse:
    row = store.get_scan(scan_id)
    if not row:
        raise fail(404, "not_found", "No such scan.")
    started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row["started"]))
    argv = " ".join(row.get("argv") or [])
    body = (
        f"# ReconKit scan - {row['tool_name']}\n\n"
        f"- Target: `{row['target']}`\n"
        f"- Tool: `{row['tool']}`\n"
        f"- Status: {row['status']} (exit {row['exit_code']})\n"
        f"- Started: {started}\n"
        f"- Duration: {round((row.get('finished') or row['started']) - row['started'], 1)}s\n\n"
        f"## Command\n\n```\n{argv}\n```\n\n"
        f"## Output\n\n```\n{row.get('output', '')}\n```\n\n"
        f"## Analysis\n\n{row.get('analysis') or '_Not analysed._'}\n"
    )
    return PlainTextResponse(
        body,
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="reconkit-{scan_id[:8]}.md"'
        },
    )


@app.get("/api/shots")
async def shots() -> dict:
    items = []
    for path in config.SHOTS.iterdir():
        if path.suffix.lower() not in {".png", ".jpg", ".jpeg", ".webp"}:
            continue
        stat = path.stat()
        items.append(
            {
                "name": path.name,
                "size": stat.st_size,
                "mtime": stat.st_mtime,
                "url": "/shots/" + quote(path.name),
            }
        )
    items.sort(key=lambda item: item["mtime"], reverse=True)
    return {"shots": items[:120]}


app.mount("/static", StaticFiles(directory=config.WEB), name="static")
app.mount("/shots", StaticFiles(directory=config.SHOTS), name="shots")
