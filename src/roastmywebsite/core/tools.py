from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class ToolStatus:
    name: str
    available: bool
    path: str | None = None
    version: str | None = None


def which(name: str) -> str | None:
    return shutil.which(name)


def tool_status(name: str) -> ToolStatus:
    path = which(name)
    if not path:
        return ToolStatus(name=name, available=False)
    version = None
    try:
        proc = subprocess.run([name, "--version"], capture_output=True, text=True, timeout=10)
        output = (proc.stdout or proc.stderr or "").strip().splitlines()
        version = output[0] if output else None
    except Exception:
        version = None
    return ToolStatus(name=name, available=True, path=path, version=version)


def run_tool(args: list[str], timeout: int = 120) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as exc:
        return 1, "", str(exc)