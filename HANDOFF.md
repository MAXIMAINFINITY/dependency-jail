# HANDOFF.md — dependency-jail
**For the next developer/model picking this up.**
This document explains everything that has been built, every design decision made, every bug fixed, and exactly what to do next. Read this fully before touching any code.

---

## 1. What Is This Project?

`dependency-jail` is a **Linux command-line security tool** that wraps package installation commands (`pip install`, `npm install`, etc.) and **blocks any unauthorized outbound network connections** made by those packages during installation.

### The threat it solves
When you run `pip install some-package`, the package's `setup.py` or build script can execute arbitrary code. A malicious package can use that window to:
- Read `~/.ssh/id_rsa`, `.env` files, `~/.aws/credentials`
- Exfiltrate your environment variables to an external server
- Download and persist a second-stage payload

`dependency-jail` prevents this by intercepting every network connection made by the installer and its child processes at the C library level, allowing only connections to known-good registries (PyPI, npm, GitHub, etc.).

---

## 2. How It Works — The Core Mechanism

This is the most important thing to understand. **Read this before looking at any code.**

### LD_PRELOAD interception
Linux uses a dynamic linker to load shared libraries at runtime. When a program calls `connect()` (the standard C function to open a network socket), it actually calls the one in `libc.so`.

By setting the environment variable `LD_PRELOAD=/path/to/libjail.so` before running a process, we force the dynamic linker to load `libjail.so` first. Since our library also defines a function named `connect()`, the linker resolves the symbol to **our version** instead of libc's.

Inside our `connect()`:
1. We parse the destination IP from the `sockaddr` argument
2. We check it against a pre-built allowlist of trusted IPs (loaded from the `JAIL_ALLOW_IPS` env var)
3. If the IP is **allowed** → we call the real `connect()` via `dlsym(RTLD_NEXT, "connect")`
4. If the IP is **blocked** → we set `errno = ECONNREFUSED` and return `-1`
5. We log the verdict to a named FIFO pipe so Python can read it in real-time

**Why this works on child processes too:** When pip runs `python setup.py build`, that child process inherits the environment variables, including `LD_PRELOAD`. So every subprocess spawned by the installer is also sandboxed automatically.

**What it does NOT intercept:**
- Loopback connections (`127.x.x.x`) — always allowed, hardcoded in C
- Unix domain sockets (file-based IPC) — always passed through
- IPv6 — currently only IPv4 is handled
- Statically linked binaries — these don't use the dynamic linker at all (not a real concern in practice since pip/npm/python are all dynamically linked)

---

## 3. Project File Structure

```
dependency-jail/
│
├── dep_jail/               ← THE REAL PYTHON PACKAGE (this is what pip installs)
│   ├── __init__.py         ← Exports: JailRunner, JailResult, compile_interceptor, RegistryResolver
│   ├── cli.py              ← CLI entry point — argument parsing, ANSI terminal output, banner
│   ├── core.py             ← Orchestrator — compiles libjail.so, runs the sandboxed command
│   ├── resolver.py         ← DNS resolver — resolves registry domains to IPs, caches them
│   └── libjail.c           ← C source code for the connect() interceptor
│
├── tests/
│   ├── __init__.py
│   └── test_jail.py        ← Unit + integration tests (10/10 passing)
│
├── src/                    ← OLD DIRECTORY — ignore this, it's a leftover from initial setup
│                             DO NOT edit files here, they are dead code
│
├── pyproject.toml          ← Package config — build system, CLI entrypoint, package discovery
├── setup.sh                ← Bash setup script for new machines
├── README.md               ← GitHub-facing documentation
├── LICENSE                 ← MIT
└── __main__.py             ← Allows `python -m dep_jail` invocation
```

### CRITICAL: The `src/` directory is dead
During setup, there was a packaging issue where the package was first put in `src/` but setuptools couldn't map it correctly to `dep_jail`. The fix was to create `dep_jail/` as a proper directory with all the same files. The `src/` directory still exists but is completely ignored by pip. **Do not edit files in `src/`. Always work in `dep_jail/`.**

---

## 4. How Each File Works

### `dep_jail/libjail.c`
Pure C, compiled to a shared object (`libjail.so`). Key functions:
- `jail_init()` — called once via `pthread_once`. Reads `JAIL_ALLOW_IPS` env var, parses each entry as a CIDR range (e.g. `151.101.0.0/22`) or plain IP, and stores them in a global array of `AllowedRange` structs (each holding a network address and mask).
- `parse_cidr(entry, out)` — converts a string like `"10.0.0.0/8"` into two uint32_t values: network and mask.
- `is_allowed(host_addr)` — checks if an IPv4 address (in host byte order) matches any range. Uses bitwise AND: `(host_addr & mask) == network`.
- `connect(sockfd, addr, addrlen)` — the intercepted function. Calls `jail_init()` once, extracts the destination IP from `addr`, runs `is_allowed()`, logs to the FIFO, and either forwards to the real `connect` or returns -1.
- `jail_log(verdict, ip, port, detail)` — formats a pipe-delimited log line and writes it to `JAIL_LOG_FIFO` (non-blocking).

**How to compile manually:**
```bash
gcc -shared -fPIC -O2 -Wall -o libjail.so dep_jail/libjail.c -ldl -lpthread
```

### `dep_jail/resolver.py`
Resolves trusted domain names to IP addresses. Key class: `RegistryResolver`.
- `DEFAULT_DOMAINS` — hardcoded dict of all trusted registry domains (PyPI, npm, GitHub, Conda, Cargo, RubyGems)
- `ALWAYS_TRUSTED_CIDRS` — RFC-1918 private ranges + loopback, always included
- `resolve()` — uses `ThreadPoolExecutor` with 16 workers to do parallel DNS lookups via `socket.getaddrinfo()`. Results cached to `~/.cache/dependency-jail/resolved_ips.json` for 1 hour.
- `get_jail_env_value()` — returns everything as a colon-separated string: `"127.0.0.0/8:10.0.0.0/8:151.101.64.223:..."`

**Cache invalidation:** Cache TTL is 3600 seconds. Bypass with `--no-cache` flag.

### `dep_jail/core.py`
The orchestrator. Key components:
- `compile_interceptor(force, log)` — checks if `libjail.so` is up-to-date by comparing a SHA-256 hash of `libjail.c` against a `.stamp` file in `~/.cache/dependency-jail/`. If stale or missing, runs gcc. Returns the path to the compiled `.so`.
- `_FifoReader` — background thread that opens the named FIFO (`os.O_RDONLY | O_NONBLOCK`), uses `select()` to poll for data, reads it in chunks, splits on newlines, and calls `_parse()` to emit structured event dicts. Started before the subprocess, stopped after it finishes.
- `JailResult` — simple data class holding `returncode`, `blocked: list[dict]`, `allowed: list[dict]`, and the `was_clean` property.
- `JailRunner.run()` — the main entry point. Calls `compile_interceptor`, then `RegistryResolver.resolve()`, creates the FIFO, builds the env dict with `LD_PRELOAD + JAIL_ALLOW_IPS + JAIL_LOG_FIFO`, runs `subprocess.run(command, env=env)`, stops the FIFO reader, returns `JailResult`.

### `dep_jail/cli.py`
The user-facing CLI. No external dependencies — only stdlib + ANSI escape codes.
- `_c(text, *codes)` — ANSI colour wrapper. Returns plain text if stdout is not a TTY (i.e., when piped or in CI).
- `_LivePrinter` — handles real-time event display. `handle(event)` is passed as the `on_event` callback to `JailRunner`.
- `_print_summary(result, elapsed)` — prints the end-of-run summary table.
- `_build_parser()` — defines all CLI flags: `--allow-domain`, `--allow-cidr`, `--verbose`, `--no-cache`, `--compile-only`, `--dry-run`, and the positional `command`.
- `main(argv)` — the entrypoint registered as `dep-jail` in `pyproject.toml`.

### `pyproject.toml` — critical config
```toml
[build-system]
requires      = ["setuptools>=45", "wheel"]
build-backend = "setuptools.build_meta"     # ← must be this exact string

[project.scripts]
dep-jail = "dep_jail.cli:main"              # ← installs the `dep-jail` command

[tool.setuptools.packages.find]
where   = ["."]
include = ["dep_jail*"]                     # ← tells setuptools to find dep_jail/

[tool.setuptools.package-data]
"dep_jail" = ["libjail.c"]                 # ← includes the C source in the installed package
```

**Why `setuptools.build_meta` and not `setuptools.backends.legacy:build`?**
The latter is an internal API path that pip's isolated build subprocess cannot import. The former is the stable, public interface that works everywhere.

---

## 5. What Has Been Tested and Works

Run `python -m pytest tests/ -v` from the project root with the venv active. All 10 tests pass:

| Test | What it verifies |
|---|---|
| `test_plain_ip_detection` | `_is_plain_ip()` correctly identifies IPs vs domains |
| `test_always_trusted_cidrs_present` | RFC-1918 ranges always in the allowlist |
| `test_extra_cidr_included` | User-supplied CIDRs are appended |
| `test_extra_domain_included` | Extra domains are resolved and added |
| `test_loopback_not_in_allowlist` | 127.0.0.0/8 in list (C handles loopback natively anyway) |
| `test_env_value_format` | `get_jail_env_value()` returns a colon-separated string |
| `test_compile_produces_so` | gcc successfully compiles libjail.c |
| `test_second_compile_uses_cache` | stamp file prevents unnecessary recompilation |
| `test_loopback_is_always_allowed` | A real socket connection to 127.0.0.1 works under the hook |
| `test_untrusted_ip_is_blocked` | A connection to 198.51.100.7 (TEST-NET-3) is blocked with ECONNREFUSED |

---

## 6. Known Issues / Limitations / Tech Debt

1. **`src/` directory is dead weight.** It still exists with duplicate copies of all source files. It should be deleted before publishing to GitHub (`rm -rf src/`). It was the original package location before the setuptools packaging was fixed.

2. **IPv6 not intercepted.** The C hook only handles `AF_INET`. If a package makes a connection over IPv6, it bypasses the sandbox entirely. Future work: add an `AF_INET6` branch to the `connect()` hook.

3. **`dep_jail/__init__.py` imports at module level.** The `from dep_jail.core import ...` in `__init__.py` runs immediately on import. This is fine for normal use but means `import dep_jail` triggers loading of `core.py` and `resolver.py`. For performance-critical use, consider lazy imports.

4. **FIFO can deadlock if the process exits too fast.** The `_FifoReader` thread opens the FIFO for reading, which blocks until a writer opens it. If the process exits before writing anything, `fifo.stop()` unblocks it by briefly opening the write end. This is working but fragile — a proper solution would use a socketpair instead of a FIFO.

5. **`tempfile.mktemp()` is technically unsafe.** It returns a path without creating the file, creating a TOCTOU race window. Safe in practice here since `os.mkfifo()` is called immediately after, but `mkstemp()` + `os.unlink()` + `os.mkfifo()` would be cleaner.

---

## 7. What To Build Next

The project is functional but not yet GitHub-presentable. Here is the prioritized backlog:

### Priority 1 — Clean up (do first)
- [ ] **Delete `src/` directory.** Run `rm -rf src/` from the project root. It's dead code.
- [ ] **Add `.gitignore`.** Should exclude: `.venv/`, `__pycache__/`, `*.egg-info/`, `.pytest_cache/`, `~/.cache/dependency-jail/` (this is outside the repo anyway).

### Priority 2 — GitHub CI (do before pushing)
- [ ] **Add `.github/workflows/test.yml`** — a GitHub Actions workflow that runs `pip install -e . && pip install pytest && python -m pytest tests/ -v` on push. This makes the README badge turn green.
  - Use `ubuntu-latest` runner (Linux is required for LD_PRELOAD to work)
  - Matrix: Python 3.10, 3.11, 3.12

### Priority 3 — Feature: `--profile` flag
Allow users to select a named registry profile instead of the full allowlist:
- `dep-jail --profile pypi pip install requests` → only trusts PyPI IPs, blocks even GitHub
- `dep-jail --profile npm npm install` → only trusts npm registry IPs
- Implement by adding a `PROFILES` dict to `resolver.py` and a `--profile` arg to the CLI

### Priority 4 — Feature: Interactive block prompt (instead of auto-block)
Instead of silently blocking and continuing, when a suspicious connection is detected, pause the installer and ask the user:
```
  ⚠  SUSPICIOUS CONNECTION DETECTED
     Process: python (setup.py build)
     Destination: 45.33.49.119:80 (attacker.io)
     Allow this connection? [y/N]:
```
This requires:
- Sending a SIGSTOP to the installer subprocess when a block event arrives
- Reading user input from the terminal
- Either sending SIGCONT (allow, and update allowlist) or keeping it blocked
- This is complex but extremely powerful UX

### Priority 5 — Feature: Report file output
After a jailed run, optionally write a JSON report:
```bash
dep-jail --report report.json pip install requests
```
The report should contain: timestamp, command, all blocked events, all allowed events, exit code.
Implement by adding a `--report PATH` flag to the CLI and writing `JailResult` to JSON at the end of `main()`.

---

## 8. How To Add a New Trusted Registry

Edit `dep_jail/resolver.py`. Add a new key to `DEFAULT_DOMAINS`:
```python
"new_registry": [
    "registry.example.com",
    "cdn.example.com",
],
```
That's it. The resolver will pick it up automatically on the next run and cache the resolved IPs.

---

## 9. How To Set Up a Fresh Machine

```bash
git clone https://github.com/USERNAME/dependency-jail.git
cd dependency-jail
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
pip install pytest
dep-jail --compile-only        # compiles libjail.so via gcc
python -m pytest tests/ -v    # should show 10/10 passing
dep-jail pip install requests  # live demo
```

Requirements: Linux, Python 3.9+, gcc (install via `sudo apt install build-essential`).

---

## 10. Coding Style Rules Used In This Project

Follow these exactly so the code stays consistent:

1. **All imports at the top of each file, stdlib only.** No third-party dependencies anywhere. This is intentional — zero deps means `pip install -e .` always works, even on minimal systems.
2. **Type hints on all function signatures.** Use `from __future__ import annotations` at the top of every Python file to enable stringified annotations (needed for Python 3.9 compatibility with `X | Y` union syntax — write it as `"X | Y"` in quotes instead, or just use `Optional[X]`).
3. **ANSI colours only when stdout is a TTY.** The `_c()` function in `cli.py` checks `sys.stdout.isatty()` before adding escape codes. Always use `_c()` — never hardcode escape codes directly in print statements.
4. **Log functions take a `log: Callable[[str], None]` argument.** Never use `print()` directly in `core.py`. This makes the module testable and allows the CLI to suppress output.
5. **C code uses `pthread_once` for initialization.** Never use global mutable state that is set from multiple threads. The `jail_init` function is called exactly once per process via `pthread_once`.
6. **Cache files go in `~/.cache/dependency-jail/`.** Never write cache files relative to the project directory. The user may have the project on a read-only filesystem.
