"""
cli.py — dependency-jail Command-Line Interface
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime
from typing import Any

from dep_jail.core import JailRunner, compile_interceptor


# ─── ANSI colour helpers ──────────────────────────────────────────────────────

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"
_RED    = "\033[38;5;196m"
_GREEN  = "\033[38;5;82m"
_YELLOW = "\033[38;5;220m"
_CYAN   = "\033[38;5;51m"
_WHITE  = "\033[38;5;255m"
_GREY   = "\033[38;5;245m"

def _c(text: str, *codes: str) -> str:
    if not sys.stdout.isatty():
        return text
    return "".join(codes) + text + _RESET


# ─── Banner ───────────────────────────────────────────────────────────────────

_BANNER = r"""
  ██████╗ ███████╗██████╗       ██╗ █████╗ ██╗██╗
  ██╔══██╗██╔════╝██╔══██╗      ██║██╔══██╗██║██║
  ██║  ██║█████╗  ██████╔╝█████╗██║███████║██║██║
  ██║  ██║██╔══╝  ██╔═══╝ ╚════╝██║██╔══██║██║██║
  ██████╔╝███████╗██║           ██║██║  ██║██║███████╗
  ╚═════╝ ╚══════╝╚═╝           ╚═╝╚═╝  ╚═╝╚═╝╚══════╝
"""

def _print_banner() -> None:
    if sys.stdout.isatty():
        print(_c(_BANNER, _CYAN, _BOLD))
        print(_c("  Supply-chain Network Sandbox  •  v1.0.0\n", _GREY))


# ─── Live event formatter ─────────────────────────────────────────────────────

class _LivePrinter:
    def __init__(self, verbose: bool) -> None:
        self._verbose = verbose
        self._blocked_count = 0
        self._allowed_count = 0

    def handle(self, event: dict) -> None:
        verdict = event.get("verdict", "")
        ip      = event.get("ip", "?")
        port    = event.get("port", 0)
        detail  = event.get("detail", "")
        ts      = datetime.fromtimestamp(event.get("ts_ms", 0) / 1000.0).strftime("%H:%M:%S")

        if verdict == "BLOCKED":
            self._blocked_count += 1
            icon  = _c("✗ BLOCKED", _RED, _BOLD)
            dest  = _c(f"{ip}:{port}", _RED)
            extra = _c(f"  ({detail})", _DIM) if detail else ""
            print(f"  {_c(ts, _GREY)}  {icon}  →  {dest}{extra}")
        elif verdict == "ALLOWED" and self._verbose:
            self._allowed_count += 1
            icon = _c("✓ allowed", _GREEN)
            dest = _c(f"{ip}:{port}", _GREY)
            print(f"  {_c(ts, _GREY)}  {icon}  →  {dest}")

    @property
    def blocked_count(self) -> int:
        return self._blocked_count

    @property
    def allowed_count(self) -> int:
        return self._allowed_count


# ─── Summary report ───────────────────────────────────────────────────────────

def _print_summary(result: Any, elapsed: float) -> None:
    blocked = result.blocked
    allowed = result.allowed

    sep = _c("─" * 62, _GREY)
    print(f"\n{sep}")
    print(_c("  dependency-jail  •  Run Summary", _BOLD, _WHITE))
    print(sep)

    status = _c("✓  CLEAN RUN", _GREEN, _BOLD) if result.was_clean else _c("✗  THREATS DETECTED", _RED, _BOLD)
    print(f"  Status      : {status}")
    print(f"  Exit code   : {_c(str(result.returncode), _YELLOW)}")
    print(f"  Duration    : {_c(f'{elapsed:.1f}s', _CYAN)}")
    print(f"  Allowed     : {_c(str(len(allowed)), _GREEN)} connections")
    print(f"  Blocked     : {_c(str(len(blocked)), _RED if blocked else _GREEN)} connections")

    if blocked:
        print(f"\n  {_c('Blocked Destinations', _RED, _BOLD)}")
        seen: set[str] = set()
        for ev in blocked:
            key = f"{ev['ip']}:{ev['port']}"
            if key not in seen:
                seen.add(key)
                print(f"    {_c('✗', _RED)}  {_c(ev['ip'], _WHITE)}:{_c(str(ev['port']), _YELLOW)}")

    print(sep + "\n")


# ─── Argument parser ──────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dep-jail",
        description="Sandbox package installations against unauthorized outbound network connections.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  dep-jail pip install requests\n"
            "  dep-jail npm ci\n"
            "  dep-jail --allow-domain my.mirror.io pip install pandas\n"
            "  dep-jail --verbose pip install -r requirements.txt\n"
            "  dep-jail --compile-only\n"
        ),
    )
    p.add_argument("--allow-domain", "-d", metavar="DOMAIN", action="append",
                   default=[], dest="allow_domains", help="Extra domain to trust (repeatable).")
    p.add_argument("--allow-cidr", "-c", metavar="CIDR", action="append",
                   default=[], dest="allow_cidrs", help="Extra CIDR block to trust (repeatable).")
    p.add_argument("--profile", "-p", metavar="PROFILE", 
                   help="Use a specific registry profile (e.g. pypi, npm, conda).")
    p.add_argument("--report", "-r", metavar="PATH",
                   help="Write a JSON report to this path after execution.")
    p.add_argument("--verbose", "-v", action="store_true", default=False,
                   help="Also log allowed connections.")
    p.add_argument("--no-cache", action="store_true", default=False,
                   help="Bypass the DNS resolver cache and perform fresh lookups.")
    p.add_argument("--compile-only", action="store_true", default=False,
                   help="Compile the interceptor library and exit.")
    p.add_argument("--dry-run", action="store_true", default=False,
                   help="Resolve the allowlist, print it, then exit.")
    p.add_argument("--doctor", action="store_true", default=False,
                   help="Check system environment and dependencies.")
    p.add_argument("--verify", action="store_true", default=False,
                   help="Run a pessimistic, zero-trust security verification.")
    p.add_argument("--release-check", action="store_true", default=False,
                   help="Run a comprehensive end-to-end release acceptance test.")
    p.add_argument("--self-test", action="store_true", default=False,
                   help="Run controlled tests to verify interception works.")
    p.add_argument("--demo", action="store_true", default=False,
                   help="Run a live demonstration of the sandbox.")
    p.add_argument("command", nargs=argparse.REMAINDER,
                   help="The package-manager command to sandbox.")
    return p


# ─── Main entrypoint ─────────────────────────────────────────────────────────

def main(argv: "list[str] | None" = None) -> int:
    parser = _build_parser()
    args   = parser.parse_args(argv)

    _print_banner()

    if args.compile_only:
        try:
            compile_interceptor(force=True, log=print)
        except RuntimeError as exc:
            print(_c(f"\n  Error: {exc}", _RED), file=sys.stderr)
            return 1
        return 0

    if args.doctor:
        from dep_jail.verify import run_doctor
        return run_doctor()
        
    if args.verify:
        from dep_jail.verify import run_verify
        return run_verify()

    if args.release_check:
        from dep_jail.verify import run_release_check
        return run_release_check()
        
    if args.self_test:
        from dep_jail.verify import run_self_test
        return run_self_test()
        
    if args.demo:
        from dep_jail.verify import run_demo
        return run_demo()

    if args.dry_run:
        from dep_jail.resolver import RegistryResolver
        print(_c("  Resolving allowlist (dry-run)…\n", _CYAN))
        r = RegistryResolver(
            extra_domains=args.allow_domains,
            extra_cidrs=args.allow_cidrs,
            profile=args.profile,
            use_cache=not args.no_cache,
        )
        r.resolve()
        entries = r.get_all_entries()
        for e in entries:
            print(f"    {_c('✓', _GREEN)}  {e}")
        print(_c(f"\n  Total: {len(entries)} entries", _BOLD))
        return 0

    if not args.command:
        parser.print_help()
        return 1

    printer = _LivePrinter(verbose=args.verbose)
    print(_c(f"  Sandboxing: {' '.join(args.command)}\n", _CYAN, _BOLD))

    runner = JailRunner(
        command=args.command,
        extra_domains=args.allow_domains,
        extra_cidrs=args.allow_cidrs,
        profile=args.profile,
        verbose=args.verbose,
        report_path=args.report,
        on_event=printer.handle,
        log=lambda msg: print(_c(msg, _DIM)),
    )

    start = time.monotonic()
    try:
        result = runner.run()
    except RuntimeError as exc:
        print(_c(f"\n  Fatal: {exc}", _RED, _BOLD), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(_c("\n\n  Interrupted by user.", _YELLOW))
        return 130

    elapsed = time.monotonic() - start
    _print_summary(result, elapsed)
    return result.returncode
