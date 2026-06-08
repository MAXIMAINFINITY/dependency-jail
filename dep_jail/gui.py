import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import queue
import sys
import time
from datetime import datetime
import shlex

from dep_jail.core import JailRunner, JailResult, compile_interceptor
from dep_jail.resolver import PROFILES

class DependencyJailGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("dependency-jail - Sandbox Installer")
        self.root.geometry("700x500")
        self.root.configure(padx=10, pady=10)

        # Thread-safe queue for UI updates
        self.queue = queue.Queue()
        self._process_queue()

        # Build UI
        self._build_ui()

        # Initialize background compiler if needed
        self.log_to_console("[System] Checking sandbox interceptor...")
        threading.Thread(target=self._init_interceptor, daemon=True).start()

    def _process_queue(self):
        try:
            while True:
                func, args = self.queue.get_nowait()
                func(*args)
        except queue.Empty:
            pass
        self.root.after(50, self._process_queue)

    def _schedule(self, func, *args):
        """Safely schedule a UI update from a background thread."""
        self.queue.put((func, args))

    def _build_ui(self):
        # Controls Frame
        controls_frame = ttk.LabelFrame(self.root, text="Sandbox Configuration", padding=(10, 10))
        controls_frame.pack(fill=tk.X, pady=(0, 10))

        # Command Input
        ttk.Label(controls_frame, text="Command:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.cmd_var = tk.StringVar(value="pip install requests")
        cmd_entry = ttk.Entry(controls_frame, textvariable=self.cmd_var, width=50)
        cmd_entry.grid(row=0, column=1, columnspan=2, sticky=tk.W, padx=5, pady=5)

        # Profile Dropdown
        ttk.Label(controls_frame, text="Profile:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.profile_var = tk.StringVar(value="pypi")
        profile_cb = ttk.Combobox(controls_frame, textvariable=self.profile_var, state="readonly", width=15)
        profile_cb['values'] = list(PROFILES.keys())
        profile_cb.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)

        # Verbose Checkbox
        self.verbose_var = tk.BooleanVar(value=True)
        verbose_cb = ttk.Checkbutton(controls_frame, text="Verbose Logging", variable=self.verbose_var)
        verbose_cb.grid(row=1, column=2, sticky=tk.W, padx=5, pady=5)

        # Run Button
        self.run_btn = ttk.Button(controls_frame, text="Run Sandboxed", command=self.start_installation)
        self.run_btn.grid(row=0, column=3, rowspan=2, sticky=tk.NSEW, padx=(10, 0))

        # Console Frame
        console_frame = ttk.LabelFrame(self.root, text="Live Monitor", padding=(5, 5))
        console_frame.pack(fill=tk.BOTH, expand=True)

        self.console = scrolledtext.ScrolledText(console_frame, wrap=tk.WORD, bg="black", fg="white", font=("Courier", 10))
        self.console.pack(fill=tk.BOTH, expand=True)

        # Tags for colors
        self.console.tag_config("info", foreground="lightblue")
        self.console.tag_config("allow", foreground="lightgreen")
        self.console.tag_config("block", foreground="red", font=("Courier", 10, "bold"))
        self.console.tag_config("error", foreground="orange")
        self.console.tag_config("summary", foreground="yellow")

    def log_to_console(self, msg, tag="info"):
        self.console.configure(state='normal')
        self.console.insert(tk.END, msg + "\n", tag)
        self.console.configure(state='disabled')
        self.console.yview(tk.END)

    def handle_event(self, event):
        self._schedule(self._process_event_ui, event)

    def _process_event_ui(self, event):
        verdict = event.get("verdict", "")
        ip = event.get("ip", "?")
        port = event.get("port", 0)
        detail = event.get("detail", "")
        ts = datetime.fromtimestamp(event.get("ts_ms", 0) / 1000.0).strftime("%H:%M:%S")

        if verdict == "BLOCKED":
            msg = f"[{ts}] ✗ BLOCKED → {ip}:{port} ({detail})"
            self.log_to_console(msg, "block")
        elif verdict == "ALLOWED" and self.verbose_var.get():
            msg = f"[{ts}] ✓ allowed → {ip}:{port}"
            self.log_to_console(msg, "allow")

    def _init_interceptor(self):
        try:
            compile_interceptor(force=False, log=lambda msg: self._schedule(self.log_to_console, msg, "info"))
        except Exception as e:
            self._schedule(self.log_to_console, f"[Error] {str(e)}", "error")

    def start_installation(self):
        cmd_str = self.cmd_var.get().strip()
        if not cmd_str:
            return

        command = shlex.split(cmd_str)
        profile = self.profile_var.get()
        verbose = self.verbose_var.get()

        self.run_btn.configure(state="disabled")
        self.console.configure(state='normal')
        self.console.delete(1.0, tk.END)
        self.console.configure(state='disabled')
        
        self.log_to_console(f"🚀 Starting sandbox: {cmd_str}")
        self.log_to_console(f"🛡️ Profile: {profile}")
        self.log_to_console("-" * 60)

        # Run in thread
        threading.Thread(target=self._run_jail, args=(command, profile, verbose), daemon=True).start()

    def _run_jail(self, command, profile, verbose):
        start_time = time.monotonic()
        try:
            runner = JailRunner(
                command=command,
                profile=profile,
                verbose=verbose,
                on_event=self.handle_event,
                log=lambda msg: self._schedule(self.log_to_console, msg, "info"),
                subprocess_out=lambda msg: self._schedule(self.log_to_console, msg, "info")
            )
            result = runner.run()
            elapsed = time.monotonic() - start_time
            self._schedule(self._show_summary, result, elapsed)
        except Exception as e:
            self._schedule(self.log_to_console, f"Fatal Error: {e}", "error")
        finally:
            self._schedule(self.run_btn.configure, {"state": "normal"})

    def _show_summary(self, result: JailResult, elapsed: float):
        self.log_to_console("-" * 60)
        if result.was_clean:
            self.log_to_console(f"✓ CLEAN RUN (Exit Code: {result.returncode})", "summary")
        else:
            self.log_to_console(f"✗ THREATS DETECTED (Exit Code: {result.returncode})", "block")
        
        self.log_to_console(f"Time: {elapsed:.1f}s | Allowed: {len(result.allowed)} | Blocked: {len(result.blocked)}", "summary")

def main():
    root = tk.Tk()
    app = DependencyJailGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
