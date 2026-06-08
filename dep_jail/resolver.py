"""
resolver.py — Trusted-Registry IP Resolver

Resolves the canonical domains of major package registries to their
current IPv4 addresses, then serialises them as a colon-separated list
for consumption by libjail.so via the JAIL_ALLOW_IPS env var.

Design goals:
  • Zero external dependencies (stdlib only).
  • Parallel DNS lookups so startup overhead is minimal (<200 ms).
  • Results are cached in ~/.cache/dependency-jail/ for offline runs.
  • The caller can inject extra domains or CIDR ranges via the config.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable

# ─── Well-known trusted registries ───────────────────────────────────────────

DEFAULT_DOMAINS: dict[str, list[str]] = {
    # Python
    "pypi": [
        "pypi.org",
        "files.pythonhosted.org",
        "pythonhosted.org",
    ],
    # Node / NPM
    "npm": [
        "registry.npmjs.org",
        "npmjs.com",
        "nodejs.org",
    ],
    # GitHub (used by both pip/npm for git-sourced deps)
    "github": [
        "github.com",
        "api.github.com",
        "objects.githubusercontent.com",
        "raw.githubusercontent.com",
        "codeload.github.com",
    ],
    # CDNs / mirrors
    "cloudflare_cdn": [
        "cdnjs.cloudflare.com",
        "1.1.1.1",
    ],
    # Conda / Anaconda
    "conda": [
        "conda.anaconda.org",
        "repo.anaconda.com",
        "pypi.anaconda.org",
    ],
    # Cargo (Rust)
    "cargo": [
        "crates.io",
        "static.crates.io",
    ],
    # RubyGems
    "rubygems": [
        "rubygems.org",
        "index.rubygems.org",
    ],
}

# Always-trusted private/link-local CIDRs (RFC-1918 + APIPA)
ALWAYS_TRUSTED_CIDRS: list[str] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "127.0.0.0/8",
    "::1/128",
]

PROFILES: dict[str, list[str]] = {
    "pypi": ["pypi", "github", "cloudflare_cdn"],
    "npm": ["npm", "github", "cloudflare_cdn"],
    "conda": ["conda", "github", "cloudflare_cdn"],
    "cargo": ["cargo", "github", "cloudflare_cdn"],
    "rubygems": ["rubygems", "github", "cloudflare_cdn"],
    "all": list(DEFAULT_DOMAINS.keys()),
}

_CACHE_DIR = Path.home() / ".cache" / "dependency-jail"
_CACHE_FILE = _CACHE_DIR / "resolved_ips.json"
_CACHE_TTL_SECONDS = 3600


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _is_plain_ip(entry: str) -> bool:
    """Return True if entry is already a raw IPv4 address or CIDR."""
    try:
        ipaddress.ip_network(entry, strict=False)
        return True
    except ValueError:
        return False


def _resolve_domain(domain: str) -> list[str]:
    if _is_plain_ip(domain):
        return [domain]
    ips = set()
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        ips.update(info[4][0] for info in infos)
    except (socket.gaierror, OSError):
        pass
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET6, socket.SOCK_STREAM)
        ips.update(info[4][0] for info in infos)
    except (socket.gaierror, OSError):
        pass
    return list(ips)


def _load_cache() -> "dict[str, list[str]] | None":
    if not _CACHE_FILE.exists():
        return None
    try:
        data = json.loads(_CACHE_FILE.read_text())
        if time.time() - data.get("_ts", 0) < _CACHE_TTL_SECONDS:
            return data
    except (json.JSONDecodeError, OSError):
        pass
    return None


def _save_cache(resolved: "dict[str, list[str]]") -> None:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    payload = {"_ts": time.time(), **resolved}
    try:
        _CACHE_FILE.write_text(json.dumps(payload, indent=2))
    except OSError:
        pass


# ─── Public API ──────────────────────────────────────────────────────────────

class RegistryResolver:
    """Resolves and caches IPs for all configured trusted registries."""

    def __init__(
        self,
        extra_domains: "Iterable[str] | None" = None,
        extra_cidrs: "Iterable[str] | None" = None,
        profile: "str | None" = None,
        use_cache: bool = True,
        max_workers: int = 16,
    ) -> None:
        self._extra_domains: list[str] = list(extra_domains or [])
        self._extra_cidrs: list[str] = list(extra_cidrs or [])
        self._profile = profile
        self._use_cache = use_cache
        self._max_workers = max_workers
        self._resolved: "dict[str, list[str]]" = {}

    def _all_domains(self) -> list[str]:
        domains: list[str] = []
        if self._profile and self._profile in PROFILES:
            keys = PROFILES[self._profile]
        else:
            keys = list(DEFAULT_DOMAINS.keys())
            
        for key in keys:
            if key in DEFAULT_DOMAINS:
                domains.extend(DEFAULT_DOMAINS[key])
                
        domains.extend(self._extra_domains)
        return list(set(domains))

    def resolve(self) -> None:
        if self._use_cache:
            cached = _load_cache()
            if cached:
                self._resolved = {k: v for k, v in cached.items() if k != "_ts"}
                return

        domains = self._all_domains()
        results: "dict[str, list[str]]" = {}

        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            future_to_domain = {pool.submit(_resolve_domain, d): d for d in domains}
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                ips = future.result()
                if ips:
                    results[domain] = ips

        self._resolved = results
        if self._use_cache:
            _save_cache(results)

    def get_all_entries(self) -> list[str]:
        entries: set[str] = set(ALWAYS_TRUSTED_CIDRS)
        entries.update(self._extra_cidrs)
        for ip_list in self._resolved.values():
            entries.update(ip_list)
        return sorted(entries)

    def get_jail_env_value(self) -> str:
        return ",".join(self.get_all_entries())

    def summary(self) -> "dict[str, list[str]]":
        return dict(self._resolved)
