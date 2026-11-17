"""Job manager: runs a tool, streams its output, persists the result.

Tools run in worker threads with subprocess.Popen so this works on any event
loop (notably on Windows). Output is polled by the SSE endpoint rather than
pushed through per-client queues - simpler, and good enough at human speed.
"""

from __future__ import annotations

import asyncio
import os
import re
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field

from . import store
from .config import DATA
from .registry import Tool

MAX_OUTPUT = 2_000_000
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
JOBS: dict[str, "Job"] = {}


@dataclass
class Job:
    id: str
    tool: str
    name: str
    target: str
    argv: list[str]
    started: float = field(default_factory=time.time)
    finished: float | None = None
    status: str = "running"
    output: list[str] = field(default_factory=list)
    size: int = 0
    truncated: bool = False
    exit_code: int | None = None
    error: str = ""
    proc: subprocess.Popen | None = None
    cancelled: bool = False
    timed_out: bool = False
    input_count: int = 0

    def text(self) -> str:
        return "".join(self.output)


def public(job: Job) -> dict:
    return {
        "id": job.id,
        "tool": job.tool,
        "tool_name": job.name,
        "target": job.target,
        "status": job.status,
        "started": job.started,
        "finished": job.finished,
        "exit_code": job.exit_code,
        "error": job.error,
        "argv": job.argv,
        "duration": round((job.finished or time.time()) - job.started, 1),
        "input_count": job.input_count,
    }


def _dump(job: Job, status: str) -> None:
    store.save_scan(
        {
            "id": job.id,
            "tool": job.tool,
            "tool_name": job.name,
            "target": job.target,
            "status": status,
            "started": job.started,
            "finished": job.finished,
            "exit_code": job.exit_code,
            "argv": job.argv,
            "output": job.text(),
            "analysis": "",
            "engine": "",
        }
    )


def _append(job: Job, text: str) -> None:
    if not text:
        return
    text = ANSI.sub("", text).replace("\r", "")
    if not text:
        return
    if job.size + len(text) > MAX_OUTPUT:
        if not job.truncated:
            job.truncated = True
            note = "\n[reconkit] output limit reached; further lines were dropped\n"
            job.output.append(note)
            job.size += len(note)
        return
    job.output.append(text)
    job.size += len(text)


def _kill(job: Job) -> None:
    proc = job.proc
    if not proc or proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True,
                creationflags=CREATE_NO_WINDOW,
                timeout=10,
            )
        else:
            proc.kill()
    except Exception:  # noqa: BLE001 - the reader thread will notice EOF either way
        try:
            proc.kill()
        except Exception:
            pass


def _finish(job: Job, status: str | None = None) -> None:
    if job.status != "running":
        return
    if job.cancelled:
        final = "cancelled"
    elif job.timed_out:
        final = "timeout"
    else:
        final = status or ("done" if job.exit_code == 0 else "failed")
    job.finished = time.time()
    # Persist first: the SSE end event and the history list key off job.status,
    # so the row must exist before the status becomes terminal.
    try:
        _dump(job, final)
    finally:
        job.status = final


def _register(job: Job) -> None:
    JOBS[job.id] = job
    finished = sorted(
        (j for j in JOBS.values() if j.status != "running"),
        key=lambda j: j.finished or 0,
    )
    while len(finished) > 40:
        old = finished.pop(0)
        JOBS.pop(old.id, None)


def start_cli(
    tool: Tool,
    target: str,
    argv: list[str],
    stdin_data: str | None,
    timeout: int,
    input_count: int = 0,
) -> Job:
    job = Job(
        id=uuid.uuid4().hex,
        tool=tool.id,
        name=tool.name,
        target=target,
        argv=argv,
        input_count=input_count,
    )
    _register(job)
    threading.Thread(target=_run_cli, args=(job, stdin_data, timeout), daemon=True).start()
    return job


def _run_cli(job: Job, stdin_data: str | None, timeout: int) -> None:
    # ReconKit's API keys are for its own HTTP calls; nuclei and friends pick
    # stray keys out of the environment and error on half-configured ones.
    env = {k: v for k, v in os.environ.items() if not k.startswith("CENSYS_")}
    env.update({"PYTHONUNBUFFERED": "1", "NO_COLOR": "1", "CLICOLOR": "0"})
    try:
        proc = subprocess.Popen(
            job.argv,
            stdin=subprocess.PIPE if stdin_data else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            cwd=str(DATA),
            env=env,
            creationflags=CREATE_NO_WINDOW,
        )
    except Exception as exc:  # noqa: BLE001 - shown in the console
        job.error = f"Could not start {job.name}: {exc}"
        _append(job, job.error + "\n")
        _finish(job, "error")
        return

    job.proc = proc
    timer = threading.Timer(timeout, lambda: _expire(job))
    timer.daemon = True
    timer.start()
    try:
        if stdin_data and proc.stdin:
            proc.stdin.write(stdin_data)
            proc.stdin.close()
        assert proc.stdout is not None
        for line in proc.stdout:
            _append(job, line)
        proc.wait(timeout=10)
        job.exit_code = proc.returncode
    except Exception as exc:  # noqa: BLE001
        job.error = f"{exc.__class__.__name__}: {exc}"
        _append(job, f"\n[reconkit] {job.error}\n")
        _kill(job)
    finally:
        timer.cancel()

    if job.truncated:
        job.output.append("[reconkit] scan ended\n")
    _finish(job)


def _expire(job: Job) -> None:
    if job.status == "running":
        job.timed_out = True
        _append(job, f"\n[reconkit] timeout after {round(time.time() - job.started)}s\n")
        _kill(job)


def start_api(tool: Tool, target: str, coro_factory) -> Job:
    job = Job(
        id=uuid.uuid4().hex,
        tool=tool.id,
        name=tool.name,
        target=target,
        argv=[],
    )
    _register(job)
    asyncio.get_running_loop().create_task(_run_api(job, coro_factory, tool.timeout))
    return job


async def _run_api(job: Job, coro_factory, timeout: int) -> None:
    try:
        text = await asyncio.wait_for(coro_factory(), timeout=timeout)
        for line in text.splitlines(True):
            _append(job, line)
        _finish(job, "done")
    except asyncio.TimeoutError:
        job.error = f"Request timed out after {round(timeout / 60)}m."
        _append(job, f"[reconkit] {job.error}\n")
        _finish(job, "timeout")
    except Exception as exc:  # noqa: BLE001
        job.error = str(exc) or exc.__class__.__name__
        _append(job, f"[reconkit] {job.error}\n")
        _finish(job, "error")


def cancel(job: Job) -> bool:
    if job.status != "running":
        return False
    job.cancelled = True
    _append(job, "\n[reconkit] stopping\n")
    _kill(job)
    return True
