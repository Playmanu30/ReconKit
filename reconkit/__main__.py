"""Launcher: python -m reconkit opens the console in your browser."""

from __future__ import annotations

import os
import threading
import webbrowser

import uvicorn

from . import config


def main() -> None:
    config.load_env()
    port = int(os.environ.get("RECON_PORT") or "8777")
    url = f"http://127.0.0.1:{port}"
    if os.environ.get("RECON_NO_BROWSER") != "1":
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    print(f"ReconKit running at {url}  (Ctrl+C to stop)")
    uvicorn.run("reconkit.app:app", host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    main()
