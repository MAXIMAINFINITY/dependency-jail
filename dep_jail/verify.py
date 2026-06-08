from __future__ import annotations

import os
import sys
import shutil
import socket
import subprocess
import tempfile
import textwrap
import time
from pathlib import Path

from dep_jail.core import compile_interceptor, _FifoReader, JailRunner

# ─── ANSI colour helpers ──────────────────────────────────────────────────────

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_RED    = "\033[38;5;196m"
_GREEN  = "\033[38;5;82m"
_YELLOW = "\033[38;5;220m"
_CYAN   = "\033[38;5;51m"
_WHITE  = "\033[38;5;255m"

def _c(text: str, *codes: str) -> str:
    if not sys.stdout.isatty():
        return text
    return "".join(codes) + text + _RESET

def _check(name: str, passed: bool, error: str = "") -> None:
    if passed:
        print(f"  {_c('✓', _GREEN)} {name}")
    else:
        print(f"  {_c('✗', _RED)} {name}")
        if error:
            print(f"      {_c(error, _RED)}")


# ─── Doctor ──────────────────────────────────────────────────────────────────

def run_doctor() -> int:
    print(_c("\n  dependency-jail • Doctor", _BOLD, _CYAN))
    print("  Checking system environment...\n")

    has_error = False

    # 1. gcc installed
    has_gcc = shutil.which("gcc") is not None
    _check("gcc compiler found", has_gcc, "Install via: sudo apt install build-essential")
    if not has_gcc: has_error = True

    # 2. compilation works
    try:
        so_path = compile_interceptor(force=False, log=lambda _: None)
        _check("interceptor compiled successfully", True)
    except Exception as e:
        _check("interceptor compiled successfully", False, str(e))
        has_error = True

    # 3. LD_PRELOAD supported
    ld_preload_works = sys.platform.startswith("linux")
    _check("LD_PRELOAD mechanism supported (Linux)", ld_preload_works, f"Current platform: {sys.platform}")
    if not ld_preload_works: has_error = True

    # 4. FIFO creation works
    try:
        fifo_path = tempfile.mktemp(prefix="jail_doctor_", suffix=".fifo")
        os.mkfifo(fifo_path, mode=0o600)
        os.unlink(fifo_path)
        _check("FIFO logging mechanism functional", True)
    except Exception as e:
        _check("FIFO logging mechanism functional", False, str(e))
        has_error = True

    # 5. DNS resolution works
    try:
        socket.gethostbyname("pypi.org")
        _check("DNS resolution functional", True)
    except Exception as e:
        _check("DNS resolution functional", False, str(e))
        has_error = True

    print("")
    if has_error:
        print(_c("  System is NOT ready. Please fix the errors above.\n", _RED, _BOLD))
        return 1
    else:
        print(_c("  System ready.\n", _GREEN, _BOLD))
        return 0


# ─── Self Test ───────────────────────────────────────────────────────────────

def run_self_test() -> int:
    print(_c("\n  dependency-jail • Self Test", _BOLD, _CYAN))
    print("  Running controlled sandbox tests...\n")

    # Create a quick script to test connections
    test_script = tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False)
    test_script.write(textwrap.dedent("""
        import socket
        import sys
        
        def try_connect(ip, port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect((ip, port))
                s.close()
                return True
            except ConnectionRefusedError:
                # This is what libjail.so returns when it blocks
                return False
            except Exception:
                # Other errors (timeout, unreachable) might happen in real life
                # but we still consider it "not blocked by sandbox" if we reach here
                return True

        # Test 1: Loopback (should always be allowed)
        t1 = try_connect("127.0.0.1", 80)
        
        # Test 2: TEST-NET-3 (RFC 5737 - 198.51.100.x) - guaranteed dead, should be blocked
        t2 = try_connect("198.51.100.7", 80)
        
        print(f"{t1},{t2}")
    """))
    test_script.close()

    try:
        runner = JailRunner(
            command=[sys.executable, test_script.name],
            verbose=True,
            log=lambda _: None
        )
        
        # We need to capture the output to verify
        # To do this cleanly, we'll patch runner to capture output
        import subprocess
        
        # Run it
        env = os.environ.copy()
        so_path = compile_interceptor(log=lambda _: None)
        allow_ips = "127.0.0.0/8" # Only allow loopback
        
        fifo_path = tempfile.mktemp()
        
        events = []
        def on_event(ev):
            events.append(ev)
            
        fifo = _FifoReader(fifo_path, on_event=on_event)
        fifo.start()
        
        env["LD_PRELOAD"] = str(so_path)
        env["JAIL_ALLOW_IPS"] = allow_ips
        env["JAIL_LOG_FIFO"] = fifo_path
        env["JAIL_VERBOSE"] = "1"
        
        proc = subprocess.run([sys.executable, test_script.name], env=env, capture_output=True, text=True)
        fifo.stop()
        
        output = proc.stdout.strip()
        
        if output == "True,False":
            _check("Test 1: Allowed connection", True)
            _check("Test 2: Blocked connection", True)
        else:
            _check("Test 1: Allowed connection", False, f"Expected True,False got {output}")
            _check("Test 2: Blocked connection", False)
            
        has_log_delivery = len(events) > 0
        _check("Test 3: Log delivery", has_log_delivery, "No events received from FIFO")
        
        print("")
        if output == "True,False" and has_log_delivery:
            print(_c("  Overall Result: WORKING\n", _GREEN, _BOLD))
            return 0
        else:
            print(_c("  Overall Result: FAILED\n", _RED, _BOLD))
            return 1
            
    finally:
        os.unlink(test_script.name)


# ─── Demo ────────────────────────────────────────────────────────────────────

def run_demo() -> int:
    print(_c("\n  dependency-jail • Live Demo", _BOLD, _CYAN))
    print("  Creating a tiny script to demonstrate sandbox interception...\n")
    
    script_content = textwrap.dedent("""
        import socket
        import sys

        def try_connect(host, port, desc, use_ipv6=False):
            print(f"    Trying to connect to {host} ({desc})...", end=" ")
            sys.stdout.flush()
            try:
                family = socket.AF_INET6 if use_ipv6 else socket.AF_INET
                s = socket.socket(family, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((host, port))
                s.close()
                print("SUCCESS")
            except Exception as e:
                print(f"FAILED ({e})")

        print("\\n  [Demo Script Executing]")
        # 1. Allowed (Python registry)
        try_connect("151.101.0.223", 443, "pypi.org IPv4")
        
        # 2. Blocked (Random external IPv4)
        try_connect("198.51.100.99", 80, "example-bad-host.test IPv4")

        # 3. Blocked (Random external IPv6)
        try_connect("2001:db8::99", 80, "example-bad-host.test IPv6", use_ipv6=True)
        print()
    """)
    
    demo_script = tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False)
    demo_script.write(script_content)
    demo_script.close()

    from dep_jail.cli import _LivePrinter
    printer = _LivePrinter(verbose=True)

    try:
        runner = JailRunner(
            command=[sys.executable, demo_script.name],
            profile="pypi",
            verbose=True,
            on_event=printer.handle,
            log=lambda _: None,
            subprocess_out=lambda msg: print(msg)
        )
        
        runner.run()
        print(_c("  Demo completed successfully.\n", _GREEN))
        return 0
    finally:
        os.unlink(demo_script.name)

# ─── Strict Verify ───────────────────────────────────────────────────────────

def run_verify() -> int:
    print(_c("\n  dependency-jail • Security Verification", _BOLD, _CYAN))
    print("  Executing pessimistic, zero-trust environment tests...\n")
    
    results = []

    def _eval(name: str, passed: bool, evidence: str) -> None:
        results.append((name, passed, evidence))
        if passed:
            print(f"  {_c('✓', _GREEN)} {name}")
            print(f"      {_c('Evidence: ' + evidence, _GREEN)}")
        else:
            print(f"  {_c('✗', _RED)} {name}")
            print(f"      {_c('Failure: ' + evidence, _RED)}")

    # 1. Compiler Availability
    has_gcc = shutil.which("gcc") is not None
    _eval("C Compiler (gcc) Availability", has_gcc, "Found at " + str(shutil.which("gcc")) if has_gcc else "gcc not found in PATH")

    # 2. Interceptor Compilation
    so_path = None
    if has_gcc:
        try:
            so_path = compile_interceptor(force=True, log=lambda _: None)
            _eval("Interceptor Compilation", True, f"libjail.so compiled successfully at {so_path}")
        except Exception as e:
            _eval("Interceptor Compilation", False, f"Compilation raised exception: {str(e)}")
    else:
        _eval("Interceptor Compilation", False, "Skipped: Pre-requisite gcc missing")

    # 3. FIFO Creation
    fifo_path = tempfile.mktemp(prefix="jail_verify_", suffix=".fifo")
    try:
        os.mkfifo(fifo_path, mode=0o600)
        os.unlink(fifo_path)
        _eval("FIFO Logging Pipeline", True, f"FIFO pipe created successfully at {fifo_path}")
    except Exception as e:
        _eval("FIFO Logging Pipeline", False, f"os.mkfifo raised exception: {str(e)}")

    # 4 & 5 & 6. IPv4/IPv6 Enforcement & Log Delivery via Subprocess
    if so_path:
        script = tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False)
        script.write(textwrap.dedent("""
            import socket
            import sys
            
            def attempt(family, ip, port):
                try:
                    s = socket.socket(family, socket.SOCK_STREAM)
                    s.settimeout(1.5)
                    s.connect((ip, port))
                    s.close()
                    return "SUCCESS"
                except ConnectionRefusedError:
                    return "ECONNREFUSED"
                except socket.timeout:
                    return "TIMEOUT"
                except OSError as e:
                    return f"OSERROR_{e.errno}"
                except Exception as e:
                    return f"ERROR_{type(e).__name__}"

            # IPv4 Allowed
            v4_allow = attempt(socket.AF_INET, "127.0.0.1", 0)
            
            # IPv4 Blocked - Google DNS TCP
            v4_block = attempt(socket.AF_INET, "8.8.8.8", 53)
            
            # IPv6 Allowed
            v6_allow = attempt(socket.AF_INET6, "::1", 0)
            
            # IPv6 Blocked - Google DNS TCP
            v6_block = attempt(socket.AF_INET6, "2001:4860:4860::8888", 53)

            print(f"{v4_allow}|{v4_block}|{v6_allow}|{v6_block}")
        """))
        script.close()

        env = os.environ.copy()
        env["LD_PRELOAD"] = str(so_path)
        # Empty allowlist: ALL external traffic must be blocked by the hook
        env["JAIL_ALLOW_IPS"] = "" 
        env["JAIL_LOG_FIFO"] = fifo_path
        env["JAIL_VERBOSE"] = "1"

        events = []
        def _on_event(ev):
            events.append(ev)

        fifo = _FifoReader(fifo_path, on_event=_on_event)
        fifo.start()

        try:
            proc = subprocess.run([sys.executable, script.name], env=env, capture_output=True, text=True, timeout=5)
            output = proc.stdout.strip().split("|")
        except Exception as e:
            output = []
            _eval("Execution Error", False, f"Subprocess crashed: {str(e)}")
        finally:
            fifo.stop()
            os.unlink(script.name)

        if len(output) == 4:
            v4_a, v4_b, v6_a, v6_b = output
            
            blocked_events = [e for e in events if e.get("verdict") == "BLOCKED"]
            has_v4_ipc = any(e.get("ip") == "8.8.8.8" for e in blocked_events)
            
            # IPv6 parsing usually compresses zeroes, but inet_ntop standardizes it. Check substrings.
            has_v6_ipc = any("2001:4860:4860::8888" in e.get("ip") for e in blocked_events)

            # Strict Verification Matrix
            v4_passed = (v4_b == "ECONNREFUSED") and has_v4_ipc
            v6_passed = (v6_b == "ECONNREFUSED") and has_v6_ipc
            
            if v4_b == "SUCCESS":
                _eval("IPv4 Hook Enforcement", False, "Critical: Subprocess successfully connected to 8.8.8.8 (Hook disabled)")
            elif not has_v4_ipc:
                _eval("IPv4 Hook Enforcement", False, f"Ambiguous: Process returned {v4_b} but no BLOCKED IPC event arrived.")
            else:
                _eval("IPv4 Hook Enforcement", v4_passed, "Hook returned ECONNREFUSED and emitted BLOCKED event for 8.8.8.8")

            if v6_b == "SUCCESS":
                _eval("IPv6 Hook Enforcement", False, "Critical: Subprocess successfully connected to 2001:4860:4860::8888 (Hook disabled)")
            elif not has_v6_ipc:
                _eval("IPv6 Hook Enforcement", False, f"Ambiguous: Process returned {v6_b} but no BLOCKED IPC event arrived.")
            else:
                _eval("IPv6 Hook Enforcement", v6_passed, "Hook returned ECONNREFUSED and emitted BLOCKED event for 2001:4860:4860::8888")
            
        else:
            _eval("IPv4 Hook Enforcement", False, "Subprocess stdout unparseable or missing")
            _eval("IPv6 Hook Enforcement", False, "Subprocess stdout unparseable or missing")

    else:
        _eval("IPv4 Hook Enforcement", False, "Skipped: Pre-requisites missing")
        _eval("IPv6 Hook Enforcement", False, "Skipped: Pre-requisites missing")

    # 7. Empty Allowlist Parsing
    # If the tests above blocked external IPs, empty allowlist logic works.
    
    passes = sum(1 for _, p, _ in results if p)
    total = len(results)
    
    print("\n  " + "─" * 60)
    if passes == total:
        print(_c(f"  VERIFICATION PASSED ({passes}/{total} checks)", _BOLD, _GREEN))
        return 0
    else:
        print(_c(f"  VERIFICATION FAILED ({passes}/{total} checks)", _BOLD, _RED))
        return 1

# ─── End-to-End Release Check ────────────────────────────────────────────────

def run_release_check() -> int:
    import tkinter as tk
    from dep_jail.gui import DependencyJailGUI
    
    print(_c("\n  dependency-jail • End-to-End Release Check", _BOLD, _CYAN))
    print("  Executing full lifecycle audit...\n")
    
    results = []
    def _eval(name: str, passed: bool) -> None:
        results.append((name, passed))
        if passed:
            print(f"  {_c('✓', _GREEN)} {name}")
        else:
            print(f"  {_c('✗', _RED)} {name}")
            
    # 1. Compile fresh
    try:
        compile_interceptor(force=True, log=lambda _: None)
        _eval("Fresh Compilation", True)
    except Exception:
        _eval("Fresh Compilation", False)
        return 1
        
    # 3. Launch GUI in test mode
    try:
        root = tk.Tk()
        # hide window
        root.withdraw()
        app = DependencyJailGUI(root)
    except Exception:
        _eval("GUI Headless Initialization", False)
        return 1

    _eval("GUI Headless Initialization", True)

    # 4 & 5. Execute Allowed Operation
    allowed_script = tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False)
    allowed_script.write(textwrap.dedent("""
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            s.connect(("pypi.org", 443))
            s.close()
        except:
            pass
    """))
    allowed_script.close()

    app.cmd_var.set(f"{sys.executable} {allowed_script.name}")
    app.profile_var.set("pypi")
    app.verbose_var.set(True)
    
    # Run the GUI action synchronously instead of threaded for the test
    # We'll just invoke _run_jail and pump Tk events
    import threading
    jail_thread = threading.Thread(target=app._run_jail, args=([sys.executable, allowed_script.name], "pypi", True))
    jail_thread.start()
    
    while jail_thread.is_alive():
        root.update()
        time.sleep(0.01)
    time.sleep(0.1)
    root.update()
    
    console_text = app.console.get("1.0", tk.END)
    allowed_passed = "✓ CLEAN RUN" in console_text and "Allowed: 1" in console_text
    _eval("GUI Backend Allowed Event Stream", allowed_passed)

    # 6 & 7. Blocked IPv4
    blocked_v4_script = tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False)
    blocked_v4_script.write(textwrap.dedent("""
        import socket, sys
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect(("8.8.8.8", 53))
        except ConnectionRefusedError:
            sys.exit(0)
        sys.exit(1)
    """))
    blocked_v4_script.close()

    app.console.configure(state='normal')
    app.console.delete("1.0", tk.END)
    app.console.configure(state='disabled')
    
    # We must use an empty profile/allowlist to force a block on 8.8.8.8
    # We can pass an empty custom profile by mocking it or just passing "npm" but 8.8.8.8 is never in it.
    jail_thread = threading.Thread(target=app._run_jail, args=([sys.executable, blocked_v4_script.name], "pypi", True))
    jail_thread.start()
    
    while jail_thread.is_alive():
        root.update()
        time.sleep(0.01)
    time.sleep(0.1)
    root.update()

    console_text = app.console.get("1.0", tk.END)
    v4_blocked = "✗ THREATS DETECTED" in console_text and "Blocked: 1" in console_text and "8.8.8.8" in console_text
    _eval("GUI Backend IPv4 Enforcement", v4_blocked)

    # 8 & 9. Blocked IPv6
    blocked_v6_script = tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False)
    blocked_v6_script.write(textwrap.dedent("""
        import socket, sys
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect(("2001:4860:4860::8888", 53))
        except ConnectionRefusedError:
            sys.exit(0)
        sys.exit(1)
    """))
    blocked_v6_script.close()

    app.console.configure(state='normal')
    app.console.delete("1.0", tk.END)
    app.console.configure(state='disabled')

    v6_events = []
    original_handle_event = app.handle_event
    def test_handle_event(event):
        v6_events.append(event)
        original_handle_event(event)
    app.handle_event = test_handle_event

    print(f"    [IPv6-DEBUG] Pre-run queue depth: {app.queue.qsize()}")

    jail_thread = threading.Thread(target=app._run_jail, args=([sys.executable, blocked_v6_script.name], "pypi", True))
    jail_thread.start()
    
    while jail_thread.is_alive():
        root.update()
        time.sleep(0.01)

    print(f"    [IPv6-DEBUG] Thread dead. Queue depth: {app.queue.qsize()}")
    time.sleep(0.1)
    root.update()
    print(f"    [IPv6-DEBUG] Post-update queue depth: {app.queue.qsize()}")

    app.handle_event = original_handle_event

    console_text = app.console.get("1.0", tk.END)
    print(f"    [IPv6-DEBUG] Raw Events: {v6_events}")
    print(f"    [IPv6-DEBUG] Console Output:\\n{console_text}")

    v6_blocked = "✗ THREATS DETECTED" in console_text and "Blocked: 1" in console_text and "2001:4860:4860::8888" in console_text
    _eval("GUI Backend IPv6 Enforcement", v6_blocked)

    os.unlink(allowed_script.name)
    os.unlink(blocked_v4_script.name)
    os.unlink(blocked_v6_script.name)
    root.destroy()

    # 10. Run Pytest
    pytest_passed = False
    try:
        proc = subprocess.run([sys.executable, "-m", "pytest", "tests/", "-q"], capture_output=True)
        if proc.returncode == 0:
            pytest_passed = True
    except:
        pass
    _eval("Pytest Suite", pytest_passed)

    # 11. Run Hardened Verifier
    # We can invoke run_verify but capture its stdout or just check return code
    import io
    from contextlib import redirect_stdout
    f = io.StringIO()
    with redirect_stdout(f):
        verify_rc = run_verify()
    _eval("Strict Verifier", verify_rc == 0)

    passes = sum(1 for _, p in results if p)
    total = len(results)
    
    print("\n  " + "─" * 60)
    print("  Release Report:")
    for name, p in results:
        status = "PASS" if p else "FAIL"
        print(f"    - {name}: {status}")

    if passes == total:
        print(_c(f"\n  RELEASE CHECK PASSED ({passes}/{total} checks)", _BOLD, _GREEN))
        return 0
    else:
        print(_c(f"\n  RELEASE CHECK FAILED ({passes}/{total} checks)", _BOLD, _RED))
        return 1
