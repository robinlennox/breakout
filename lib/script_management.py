#!/usr/bin/env python3
"""Process-management helpers for Breakout."""

import atexit
import logging
import os
import subprocess
import sys
from pathlib import Path

log = logging.getLogger("breakout")

_PID_DIR = Path("/tmp")


def check_running_state(process_name: str) -> None:
    """Exit if another instance of *process_name* is already running.

    Uses a PID file to reliably detect duplicates without false
    positives from IDE processes or sudo wrappers.
    """
    pid_file = _PID_DIR / f"breakout_{process_name}.pid"

    if pid_file.exists():
        try:
            old_pid = int(pid_file.read_text().strip())
            # Check if that PID is still alive
            os.kill(old_pid, 0)
            # Process exists — check it's actually python running our script
            cmdline = Path(f"/proc/{old_pid}/cmdline").read_text()
            if process_name in cmdline:
                log.error(f"{process_name} already running (PID {old_pid})")
                sys.exit(0)
        except (ProcessLookupError, PermissionError, FileNotFoundError, ValueError):
            # Old process is gone — stale PID file, we can proceed
            pass

    # Write our PID and register cleanup
    pid_file.write_text(str(os.getpid()))
    atexit.register(lambda: pid_file.unlink(missing_ok=True))

