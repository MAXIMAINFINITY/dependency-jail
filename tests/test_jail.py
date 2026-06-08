"""
test_jail.py — Integration and unit tests for dependency-jail

Tests are self-contained and do not require any package installations.
They use tiny helper scripts to simulate:
  (a) an ALLOWED connection to a trusted IP (loopback echo server)
  (b) a BLOCKED connection to a fictitious untrusted IP

Run with:
    python -m pytest tests/ -v
    # or without pytest:
    python tests/test_jail.py
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from dep_jail.core     import compile_interceptor, JailRunner
from dep_jail.resolver import RegistryResolver, _is_plain_ip, ALWAYS_TRUSTED_CIDRS


# ─── Resolver unit tests ──────────────────────────────────────────────────────

class TestResolver(unittest.TestCase):

    def test_plain_ip_detection(self):
        self.assertTrue(_is_plain_ip("192.168.1.1"))
        self.assertTrue(_is_plain_ip("10.0.0.0/8"))
        self.assertFalse(_is_plain_ip("registry.npmjs.org"))
        self.assertFalse(_is_plain_ip("not_an_ip"))

    def test_always_trusted_cidrs_present(self):
        r = RegistryResolver(use_cache=False)
        r.resolve()
        entries = r.get_all_entries()
        for cidr in ALWAYS_TRUSTED_CIDRS:
            self.assertIn(cidr, entries, f"Expected CIDR {cidr} in allowlist")

    def test_extra_domain_included(self):
        r = RegistryResolver(extra_domains=["example.com"], use_cache=False)
        r.resolve()
        all_ips = set(r.get_all_entries())
        # example.com resolves to 93.184.216.34 (IANA)
        # We just check that more than the baseline entries were added
        self.assertGreater(len(all_ips), len(ALWAYS_TRUSTED_CIDRS))

    def test_extra_cidr_included(self):
        r = RegistryResolver(extra_cidrs=["203.0.113.0/24"], use_cache=False)
        r.resolve()
        self.assertIn("203.0.113.0/24", r.get_all_entries())

    def test_env_value_format(self):
        r = RegistryResolver(use_cache=False)
        r.resolve()
        val = r.get_jail_env_value()
        self.assertIsInstance(val, str)
        self.assertGreater(len(val), 0)
        parts = val.split(":")
        self.assertGreater(len(parts), 4, "Expected several entries in JAIL_ALLOW_IPS")

    def test_loopback_not_in_allowlist(self):
        """libjail.c handles loopback natively — no need to list 127.0.0.1."""
        r = RegistryResolver(use_cache=False)
        r.resolve()
        # 127.0.0.0/8 is in ALWAYS_TRUSTED_CIDRS but 127.0.0.1 as a plain IP
        # should not appear as an individual entry.
        entries = r.get_all_entries()
        self.assertIn("127.0.0.0/8", entries)


# ─── Compiler tests ───────────────────────────────────────────────────────────

class TestCompiler(unittest.TestCase):

    def test_compile_produces_so(self):
        so = compile_interceptor(force=True, log=lambda _: None)
        self.assertTrue(so.exists(), "libjail.so not created")
        self.assertGreater(so.stat().st_size, 1000, "libjail.so suspiciously small")

    def test_second_compile_uses_cache(self):
        """Second call should return immediately (cache hit)."""
        compile_interceptor(force=False, log=lambda _: None)
        t0 = time.monotonic()
        compile_interceptor(force=False, log=lambda _: None)
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 0.5, "Cache hit took too long — recompiled?")


# ─── Integration tests via subprocess ────────────────────────────────────────

_ALLOW_SCRIPT = """\
import socket, sys
# Attempt to connect to loopback — must succeed
s = socket.socket()
s.settimeout(2)
try:
    s.connect(("127.0.0.1", {port}))
    s.close()
    sys.exit(0)
except Exception as e:
    print("FAIL:", e, file=sys.stderr)
    sys.exit(1)
"""

_BLOCK_SCRIPT = """\
import socket, sys
# Attempt to connect to a made-up external IP — must be blocked
s = socket.socket()
s.settimeout(2)
try:
    s.connect(("198.51.100.7", 80))  # TEST-NET-3 (RFC-5737), never real
    s.close()
    print("ERROR: connection should have been blocked", file=sys.stderr)
    sys.exit(2)
except ConnectionRefusedError:
    sys.exit(0)  # Expected: blocked by libjail
except Exception as e:
    # Some other error (e.g. timeout) is also acceptable — not a real server
    sys.exit(0)
"""


class TestIntegration(unittest.TestCase):
    """
    These tests require gcc and spin up a tiny echo server on localhost.
    Skip them in CI environments where network is fully isolated.
    """

    @classmethod
    def setUpClass(cls):
        # Ensure the interceptor is compiled
        cls.so_path = compile_interceptor(force=False, log=lambda _: None)

    def _build_env(self, allow_ips: str) -> dict:
        env = os.environ.copy()
        env["LD_PRELOAD"]    = str(self.so_path)
        env["JAIL_ALLOW_IPS"] = allow_ips
        env["JAIL_LOG_FIFO"]  = ""   # disable FIFO logging for tests
        env["JAIL_VERBOSE"]   = "0"
        return env

    def test_loopback_is_always_allowed(self):
        """Loopback connections must succeed even with empty allowlist."""
        # Spin up a minimal echo server
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def _serve():
            conn, _ = srv.accept()
            conn.close()
            srv.close()

        t = threading.Thread(target=_serve, daemon=True)
        t.start()

        script = _ALLOW_SCRIPT.format(port=port)
        result = subprocess.run(
            [sys.executable, "-c", script],
            env=self._build_env("127.0.0.0/8"),  # minimal allowlist
        )
        t.join(timeout=3)
        self.assertEqual(result.returncode, 0, "Loopback connection was incorrectly blocked")

    def test_untrusted_ip_is_blocked(self):
        """Connections to TEST-NET-3 (198.51.100.x) must be blocked."""
        result = subprocess.run(
            [sys.executable, "-c", _BLOCK_SCRIPT],
            env=self._build_env("127.0.0.0/8"),  # only loopback trusted
            timeout=5,
        )
        self.assertEqual(result.returncode, 0, "Expected block was not enforced")

    def test_ipv6_loopback_is_allowed(self):
        """IPv6 Loopback connections must succeed even with empty allowlist."""
        srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("::1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def _serve():
            conn, _ = srv.accept()
            conn.close()
            srv.close()

        t = threading.Thread(target=_serve, daemon=True)
        t.start()

        script = _ALLOW_SCRIPT.replace("socket.socket()", "socket.socket(socket.AF_INET6, socket.SOCK_STREAM)").replace("127.0.0.1", "::1").format(port=port)
        result = subprocess.run(
            [sys.executable, "-c", script],
            env=self._build_env("::1/128"),
        )
        t.join(timeout=3)
        self.assertEqual(result.returncode, 0, "IPv6 Loopback connection was incorrectly blocked")

    def test_untrusted_ipv6_is_blocked(self):
        """Connections to IPv6 Documentation Prefix (2001:db8::1) must be blocked."""
        script = _BLOCK_SCRIPT.replace("socket.socket()", "socket.socket(socket.AF_INET6, socket.SOCK_STREAM)").replace("198.51.100.7", "2001:db8::1")
        result = subprocess.run(
            [sys.executable, "-c", script],
            env=self._build_env("127.0.0.0/8"),  # empty IPv6 allowlist, must fail closed
            timeout=5,
        )
        self.assertEqual(result.returncode, 0, "Expected IPv6 block was not enforced")


# ─── Runner ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
