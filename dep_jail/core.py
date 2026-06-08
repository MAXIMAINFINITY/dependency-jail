"""
core.py — dependency-jail Runner Engine
"""

from __future__ import annotations

import hashlib
import json
import os
import select
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Callable

from dep_jail.resolver import RegistryResolver

# ─── Paths ───────────────────────────────────────────────────────────────────

_PACKAGE_DIR  = Path(__file__).parent
_C_SOURCE     = _PACKAGE_DIR / "libjail.c"
_SO_CACHE_DIR = Path.home() / ".cache" / "dependency-jail"
_SO_PATH      = _SO_CACHE_DIR / "libjail.so"


# ─── Compilation ─────────────────────────────────────────────────────────────

def _source_hash() -> str:
    return hashlib.sha256(_C_SOURCE.read_bytes()).hexdigest()[:16]


def _so_is_fresh() -> bool:
    stamp = _SO_PATH.with_suffix(".stamp")
    if not _SO_PATH.exists() or not stamp.exists():
        return False
    return stamp.read_text().strip() == _source_hash()


def compile_interceptor(force: bool = False, log: Callable[[str], None] = print) -> Path:
    """Compile libjail.c → libjail.so if not already up-to-date."""
    _SO_CACHE_DIR.mkdir(parents=True, exist_ok=True)

    if not force and _so_is_fresh():
        log(f"  ✓  Interceptor library up-to-date: {_SO_PATH}")
        return _SO_PATH

    if not shutil.which("gcc"):
        raise RuntimeError(
            "gcc not found. Install build-essential:\n"
            "  sudo apt install build-essential"
        )

    log("  ⚙  Compiling network interceptor…")
    cmd = [
        "gcc", "-shared", "-fPIC", "-O2", "-Wall",
        "-o", str(_SO_PATH),
        str(_C_SOURCE),
        "-ldl", "-lpthread",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Compilation failed:\n{result.stderr}")

    _SO_PATH.with_suffix(".stamp").write_text(_source_hash())
    log(f"  ✓  Compiled → {_SO_PATH}")
    return _SO_PATH


# ─── FIFO log reader ─────────────────────────────────────────────────────────

class _FifoReader:
    def __init__(self, fifo_path: str, on_event: Callable[[dict], None]) -> None:
        self._path     = fifo_path
        self._on_event = on_event
        self._stop     = threading.Event()
        self._thread   = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        try:
            os.mkfifo(self._path, mode=0o600)
        except FileExistsError:
            pass
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            fd = os.open(self._path, os.O_WRONLY | os.O_NONBLOCK)
            os.close(fd)
        except OSError:
            pass
        self._thread.join(timeout=2)
        try:
            os.unlink(self._path)
        except OSError:
            pass

    def _run(self) -> None:
        try:
            fd = os.open(self._path, os.O_RDONLY | os.O_NONBLOCK)
        except OSError:
            return
        buf = b""
        while not self._stop.is_set():
            rlist, _, _ = select.select([fd], [], [], 0.2)
            if fd in rlist:
                try:
                    chunk = os.read(fd, 4096)
                except BlockingIOError:
                    continue
                except OSError:
                    break
                if chunk:
                    buf += chunk
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        self._parse(line.decode(errors="replace"))
        os.close(fd)

    def _parse(self, line: str) -> None:
        parts = line.split("|", 4)
        if len(parts) < 4:
            return
        epoch_ms, verdict, ip, port, *rest = parts
        self._on_event({
            "ts_ms":   int(epoch_ms) if epoch_ms.isdigit() else 0,
            "verdict": verdict,
            "ip":      ip,
            "port":    int(port) if port.isdigit() else 0,
            "detail":  rest[0] if rest else "",
        })


# ─── Public API ──────────────────────────────────────────────────────────────

class JailResult:
    def __init__(self) -> None:
        self.returncode: int = 0
        self.blocked: list[dict] = []
        self.allowed: list[dict] = []

    @property
    def was_clean(self) -> bool:
        return len(self.blocked) == 0


class JailRunner:
    def __init__(
        self,
        command: list[str],
        extra_domains: "list[str] | None" = None,
        extra_cidrs: "list[str] | None" = None,
        profile: "str | None" = None,
        verbose: bool = False,
        report_path: "str | None" = None,
        on_event: "Callable[[dict], None] | None" = None,
        log: Callable[[str], None] = print,
        subprocess_out: "Callable[[str], None] | None" = None,
    ) -> None:
        self.command       = command
        self.extra_domains = extra_domains or []
        self.extra_cidrs   = extra_cidrs   or []
        self.profile       = profile
        self.verbose       = verbose
        self.report_path   = report_path
        self.on_event      = on_event
        self.log           = log
        self.subprocess_out = subprocess_out
        self._result       = JailResult()

    def _handle_event(self, event: dict) -> None:
        if event["verdict"] == "BLOCKED":
            self._result.blocked.append(event)
        else:
            self._result.allowed.append(event)
        if self.on_event:
            self.on_event(event)

    def run(self) -> JailResult:
        so_path = compile_interceptor(log=self.log)

        self.log("  🔍  Resolving trusted registry IPs…")
        resolver = RegistryResolver(
            extra_domains=self.extra_domains,
            extra_cidrs=self.extra_cidrs,
            profile=self.profile,
        )
        resolver.resolve()
        allow_ips = resolver.get_jail_env_value()
        self.log(f"  ✓  Allowlist built: {len(allow_ips.split(':'))} entries")

        fifo_path = tempfile.mktemp(prefix="jail_", suffix=".fifo")
        fifo = _FifoReader(fifo_path, on_event=self._handle_event)
        fifo.start()

        env = os.environ.copy()
        env["LD_PRELOAD"]     = str(so_path)
        env["JAIL_ALLOW_IPS"] = allow_ips
        env["JAIL_LOG_FIFO"]  = fifo_path
        env["JAIL_VERBOSE"]   = "1" if self.verbose else "0"

        self.log(f"\n  🚀  Running: {' '.join(self.command)}\n")
        
        if self.subprocess_out:
            proc = subprocess.Popen(
                self.command, 
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            for line in iter(proc.stdout.readline, ''):
                self.subprocess_out(line.rstrip('\n'))
            proc.stdout.close()
            proc.wait()
            self._result.returncode = proc.returncode
        else:
            proc = subprocess.run(self.command, env=env)
            self._result.returncode = proc.returncode

        fifo.stop()
        
        if self.report_path:
            import time
            report_data = {
                "timestamp": time.time(),
                "command": self.command,
                "exit_code": self._result.returncode,
                "blocked": self._result.blocked,
                "allowed": self._result.allowed,
            }
            try:
                Path(self.report_path).write_text(json.dumps(report_data, indent=2))
                self.log(f"  ✓  Report written to: {self.report_path}")
            except Exception as e:
                self.log(f"  ✗  Failed to write report: {e}")

        return self._result
