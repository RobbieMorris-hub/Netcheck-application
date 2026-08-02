gui.py

"""Tkinter desktop interface for netcheck.

The probes are slow - traceroute alone can take up to 90 seconds - so they run
on a worker thread and report back through a queue that the Tk main loop
drains. Tk widgets are only ever touched from the main thread.
"""

from __future__ import annotations

import os
import queue
import sys
import threading
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

from . import __version__
from .analyzer import API_KEY_ENV, DEFAULT_PROVIDER, PROVIDERS, analyze
from .cli import EFFORT_LEVELS, render
from .core import Report, TargetError, normalize_target
from .runner import (
    DEFAULT_PORTS,
    ProbeResult,
    run_dns,
    run_ping,
    run_port_checks,
    run_traceroute,
)

POLL_MS = 100
MONO = ("Consolas", 9)
PROBE_LABELS = {
    "ping": "Ping",
    "traceroute": "Traceroute",
    "dns": "DNS",
    "ports": "TCP ports",
}
# The Anthropic SDK also accepts an auth token or an `ant auth login` profile,
# so a missing API key alone does not mean the AI step is unavailable.
EXTRA_CREDENTIALS = {"anthropic": ("ANTHROPIC_AUTH_TOKEN",)}


def parse_ports(text: str) -> list[int]:
    """Parse the ports field: comma- or space-separated, deduplicated."""
    ports: list[int] = []
    for chunk in text.replace(",", " ").split():
        try:
            port = int(chunk)
        except ValueError:
            raise ValueError(f"{chunk!r} is not a port number") from None
        if not 1 <= port <= 65535:
            raise ValueError(f"port {port} is outside the range 1-65535")
        if port not in ports:
            ports.append(port)
    return ports


def credential_hint(provider: str) -> str | None:
    """Return a warning if no credential appears to be configured."""
    names = (API_KEY_ENV.get(provider, ""), *EXTRA_CREDENTIALS.get(provider, ()))
    if any(os.environ.get(name) for name in names if name):
        return None
    return f"{API_KEY_ENV.get(provider, 'An API key')} is not set - the AI step may be skipped."


class ProbeWorker(threading.Thread):
    """Runs the probe suite off the UI thread, posting progress to a queue.

    Messages are ``(kind, payload)`` tuples. Cancellation is checked between
    probes: an in-flight subprocess is left to finish under its own timeout
    rather than being killed mid-run.
    """

    def __init__(self, target: str, ports: list[int], options: dict, outbox: queue.Queue):
        super().__init__(daemon=True)
        self.target = target
        self.ports = ports
        self.options = options
        self.outbox = outbox
        self.cancelled = threading.Event()

    def cancel(self) -> None:
        self.cancelled.set()

    def run(self) -> None:
        try:
            host = normalize_target(self.target)
        except TargetError as exc:
            self.outbox.put(("failed", str(exc)))
            return

        self.outbox.put(("host", host))
        steps = [("ping", run_ping), ("traceroute", run_traceroute), ("dns", run_dns)]
        if self.ports:
            steps.append(("ports", lambda h: run_port_checks(h, self.ports)))

        probes: list[ProbeResult] = []
        for name, probe in steps:
            if self.cancelled.is_set():
                self.outbox.put(("cancelled", probes))
                return
            self.outbox.put(("probe_start", name))
            try:
                result = probe(host)
            except Exception as exc:  # a broken probe must not kill the run
                self.outbox.put(("probe_error", (name, str(exc))))
                continue
            probes.append(result)
            self.outbox.put(("probe_done", result))

        if self.cancelled.is_set():
            self.outbox.put(("cancelled", probes))
            return

        diagnosis = None
        if self.options["use_ai"] and probes:
            self.outbox.put(("diagnosis_start", None))
            diagnosis = analyze(
                host, probes, self.options["provider"], self.options["effort"]
            )
            self.outbox.put(("diagnosis_done", diagnosis))

        self.outbox.put(("finished", Report(host, probes, diagnosis)))


class NetcheckApp(ttk.Frame):
    """The main window."""

    def __init__(self, master: tk.Tk):
        super().__init__(master, padding=10)
        self.master.title(f"netcheck {__version__}")
        self.master.minsize(760, 560)
        self.pack(fill="both", expand=True)

        self.outbox: queue.Queue = queue.Queue()
        self.worker: ProbeWorker | None = None
        self.report: Report | None = None
        self.host = ""
        self._steps_done = 0

        self.target_var = tk.StringVar()
        self.ports_var = tk.StringVar(value=", ".join(str(p) for p in DEFAULT_PORTS))
        self.ai_var = tk.BooleanVar(value=True)
        self.provider_var = tk.StringVar(value=DEFAULT_PROVIDER)
        self.effort_var = tk.StringVar(value="medium")
        self.status_var = tk.StringVar(value="Ready.")
        self.cred_var = tk.StringVar()

        self._build_controls()
        self._build_status()
        self._build_output()
        self._refresh_credentials()
        self.after(POLL_MS, self._drain)

    # ---------------------------------------------------------------- layout

    def _build_controls(self) -> None:
        box = ttk.LabelFrame(self, text="Target", padding=8)
        box.pack(fill="x")
        box.columnconfigure(1, weight=1)

        ttk.Label(box, text="Host or URL:").grid(row=0, column=0, sticky="w", padx=(0, 6))
        entry = ttk.Entry(box, textvariable=self.target_var)
        entry.grid(row=0, column=1, sticky="ew")
        entry.bind("<Return>", lambda _event: self.start())
        entry.focus_set()

        self.run_btn = ttk.Button(box, text="Run", command=self.start)
        self.run_btn.grid(row=0, column=2, padx=(6, 0))
        self.cancel_btn = ttk.Button(box, text="Cancel", command=self.stop, state="disabled")
        self.cancel_btn.grid(row=0, column=3, padx=(4, 0))

        ttk.Label(box, text="TCP ports:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(box, textvariable=self.ports_var).grid(
            row=1, column=1, columnspan=3, sticky="ew", pady=(8, 0)
        )

        ai = ttk.Frame(box)
        ai.grid(row=2, column=0, columnspan=4, sticky="ew", pady=(8, 0))
        ttk.Checkbutton(
            ai, text="AI diagnosis", variable=self.ai_var, command=self._refresh_credentials
        ).pack(side="left")
        ttk.Label(ai, text="Provider:").pack(side="left", padx=(12, 4))
        self.provider_box = ttk.Combobox(
            ai, textvariable=self.provider_var, values=list(PROVIDERS),
            state="readonly", width=10,
        )
        self.provider_box.pack(side="left")
        self.provider_box.bind("<<ComboboxSelected>>", lambda _e: self._refresh_credentials())
        ttk.Label(ai, text="Effort:").pack(side="left", padx=(12, 4))
        self.effort_box = ttk.Combobox(
            ai, textvariable=self.effort_var, values=list(EFFORT_LEVELS),
            state="readonly", width=8,
        )
        self.effort_box.pack(side="left")
        ttk.Label(ai, textvariable=self.cred_var, foreground="#b45309").pack(
            side="left", padx=(12, 0)
        )

    def _build_status(self) -> None:
        box = ttk.LabelFrame(self, text="Progress", padding=8)
        box.pack(fill="x", pady=(10, 0))

        self.tree = ttk.Treeview(
            box, columns=("state", "time"), show="tree headings", height=5
        )
        self.tree.heading("#0", text="Probe")
        self.tree.heading("state", text="Result")
        self.tree.heading("time", text="Elapsed")
        self.tree.column("#0", width=140, anchor="w")
        self.tree.column("state", width=420, anchor="w")
        self.tree.column("time", width=80, anchor="e")
        self.tree.pack(fill="x")

        self.progress = ttk.Progressbar(box, mode="determinate")
        self.progress.pack(fill="x", pady=(8, 0))
        ttk.Label(box, textvariable=self.status_var).pack(anchor="w", pady=(4, 0))

    def _build_output(self) -> None:
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, pady=(10, 0))

        self.diagnosis_text = self._make_tab(notebook, "AI diagnosis")
        self.raw_text = self._make_tab(notebook, "Raw output")
        self.notebook = notebook

        actions = ttk.Frame(self)
        actions.pack(fill="x", pady=(8, 0))
        self.save_btn = ttk.Button(actions, text="Save report...", command=self.save, state="disabled")
        self.save_btn.pack(side="left")
        self.copy_btn = ttk.Button(actions, text="Copy to clipboard", command=self.copy, state="disabled")
        self.copy_btn.pack(side="left", padx=(6, 0))

    def _make_tab(self, notebook: ttk.Notebook, title: str) -> tk.Text:
        frame = ttk.Frame(notebook)
        notebook.add(frame, text=title)
        text = tk.Text(frame, wrap="word", font=MONO, height=16, relief="flat", padx=6, pady=6)
        scroll = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set, state="disabled")
        text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        return text

    # ------------------------------------------------------------- utilities

    def _set_text(self, widget: tk.Text, content: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", content)
        widget.configure(state="disabled")

    def _refresh_credentials(self) -> None:
        if not self.ai_var.get():
            self.cred_var.set("")
            self.provider_box.state(["disabled"])
            self.effort_box.state(["disabled"])
            return
        self.provider_box.state(["!disabled"])
        self.effort_box.state(["!disabled" if self.provider_var.get() == "anthropic" else "disabled"])
        self.cred_var.set(credential_hint(self.provider_var.get()) or "")

    def _set_busy(self, busy: bool) -> None:
        self.run_btn.configure(state="disabled" if busy else "normal")
        self.cancel_btn.configure(state="normal" if busy else "disabled")
        finished = self.report is not None
        for button in (self.save_btn, self.copy_btn):
            button.configure(state="normal" if finished and not busy else "disabled")

    # --------------------------------------------------------------- actions

    def start(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("netcheck", "Enter a host, IP address, or URL.")
            return
        try:
            ports = parse_ports(self.ports_var.get())
        except ValueError as exc:
            messagebox.showerror("netcheck", f"Invalid ports: {exc}")
            return

        self.report = None
        self.host = ""
        self._steps_done = 0
        self._reset_progress()
        self._set_text(self.raw_text, "")
        self._set_text(self.diagnosis_text, "")
        self.tree.delete(*self.tree.get_children())
        names = ["ping", "traceroute", "dns"] + (["ports"] if ports else [])
        for name in names:
            self.tree.insert("", "end", iid=name, text=PROBE_LABELS[name], values=("queued", ""))

        options = {
            "use_ai": self.ai_var.get(),
            "provider": self.provider_var.get(),
            "effort": self.effort_var.get(),
        }
        # The diagnosis is its own step, so the bar only counts it when enabled.
        self.progress.configure(maximum=len(names) + (1 if options["use_ai"] else 0), value=0)
        self.status_var.set(f"Running {len(names)} probes against {target}...")
        self.worker = ProbeWorker(target, ports, options, self.outbox)
        self.worker.start()
        self._set_busy(True)

    def stop(self) -> None:
        if self.worker and self.worker.is_alive():
            self.worker.cancel()
            self.status_var.set("Cancelling - waiting for the current probe to finish...")
            self.cancel_btn.configure(state="disabled")
            # The in-flight subprocess is left to finish under its own timeout,
            # which is up to 90s for traceroute. Pulse the bar so the window
            # does not look hung while that plays out.
            self.progress.configure(mode="indeterminate")
            self.progress.start(15)

    def _reset_progress(self) -> None:
        self.progress.stop()
        self.progress.configure(mode="determinate")

    def save(self) -> None:
        if not self.report:
            return
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = filedialog.asksaveasfilename(
            title="Save report",
            defaultextension=".txt",
            initialfile=f"netcheck-{self.report.host}-{stamp}.txt",
            filetypes=[("Text report", "*.txt"), ("JSON report", "*.json")],
        )
        if not path:
            return
        try:
            if path.lower().endswith(".json"):
                import json

                content = json.dumps(self.report.as_dict(), indent=2, ensure_ascii=False)
            else:
                content = render(self.report)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(content)
        except OSError as exc:
            messagebox.showerror("netcheck", f"Could not save the report: {exc}")
            return
        self.status_var.set(f"Saved to {path}")

    def copy(self) -> None:
        if not self.report:
            return
        self.clipboard_clear()
        self.clipboard_append(render(self.report))
        self.status_var.set("Report copied to the clipboard.")

    # ---------------------------------------------------------- message pump

    def _drain(self) -> None:
        """Apply queued worker messages. Runs on the Tk thread only."""
        try:
            while True:
                kind, payload = self.outbox.get_nowait()
                self._handle(kind, payload)
        except queue.Empty:
            pass
        self.after(POLL_MS, self._drain)

    def _advance(self) -> None:
        """Move the progress bar on one step.

        Set the value directly rather than calling ``step()``, which wraps back
        to zero on reaching the maximum - emptying the bar just as the run ends.
        """
        self._steps_done += 1
        self.progress.configure(value=min(self._steps_done, self.progress["maximum"]))

    def _handle(self, kind: str, payload) -> None:
        if kind == "host":
            self.host = payload
            self.status_var.set(f"Probing {payload}...")

        elif kind == "probe_start":
            self.tree.set(payload, "state", "running...")

        elif kind == "probe_done":
            result: ProbeResult = payload
            if result.exit_code is None:
                state = "could not run"
            elif result.ok:
                state = "ok"
            else:
                state = f"problem (exit {result.exit_code})"
            self.tree.set(result.name, "state", state)
            self.tree.set(result.name, "time", f"{result.elapsed_s:.1f}s")
            self._advance()
            self._append_raw(result)

        elif kind == "probe_error":
            name, message = payload
            self.tree.set(name, "state", f"error: {message}")
            self._advance()

        elif kind == "diagnosis_start":
            self.status_var.set("Probes complete. Asking the model for a diagnosis...")
            self._set_text(self.diagnosis_text, "Waiting for the model...")

        elif kind == "diagnosis_done":
            self._advance()
            if payload.ok:
                self._set_text(self.diagnosis_text, payload.text)
                self.status_var.set(f"Diagnosis complete ({payload.provider}/{payload.model}).")
            else:
                hint = credential_hint(payload.provider)
                message = f"AI diagnosis unavailable:\n\n{payload.error}"
                if hint:
                    message += f"\n\n{hint}"
                self._set_text(self.diagnosis_text, message)
                self.status_var.set("Probes complete; AI diagnosis unavailable.")
            self.notebook.select(0)

        elif kind == "finished":
            self.report = payload
            healthy = "all probes healthy" if payload.all_ok else "one or more probes reported a problem"
            if not payload.diagnosis:
                self.status_var.set(f"Done - {healthy}. AI diagnosis was disabled.")
                self.notebook.select(1)
            elif payload.diagnosis.ok:
                self.status_var.set(f"Done - {healthy}.")
            self._set_busy(False)

        elif kind == "cancelled":
            self._reset_progress()
            self.report = Report(self.host, payload, None) if payload else None
            self.status_var.set("Cancelled.")
            for name in self.tree.get_children():
                if self.tree.set(name, "state") in ("queued", "running..."):
                    self.tree.set(name, "state", "skipped")
            self._set_busy(False)

        elif kind == "failed":
            self._reset_progress()
            self.status_var.set(f"Error: {payload}")
            messagebox.showerror("netcheck", payload)
            self._set_busy(False)

    def _append_raw(self, result: ProbeResult) -> None:
        header = f"--- {result.name} ---\n$ {result.command}\n\n"
        self.raw_text.configure(state="normal")
        self.raw_text.insert("end", header + (result.output or "(no output)") + "\n\n")
        self.raw_text.see("end")
        self.raw_text.configure(state="disabled")


def main(argv: list[str] | None = None) -> int:
    """Launch the GUI. An optional argument pre-fills the target field."""
    argv = sys.argv[1:] if argv is None else argv

    # Handle the two flags people reflexively try, so they don't end up sitting
    # in the target field as though they were a hostname.
    if argv and argv[0] in ("-h", "--help"):
        print(
            f"netcheck-gui {__version__}\n\n"
            "Usage: netcheck-gui [TARGET]\n\n"
            "Opens the netcheck desktop window. TARGET optionally pre-fills\n"
            "the host field. For the command-line tool, run: netcheck --help"
        )
        return 0
    if argv and argv[0] in ("-V", "--version"):
        print(f"netcheck-gui {__version__}")
        return 0

    if os.name == "nt":
        # Without this the window renders blurry on high-DPI displays.
        try:
            from ctypes import windll

            windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(f"error: no display available ({exc})", file=sys.stderr)
        return 1

    style = ttk.Style()
    for theme in ("vista", "clam"):
        if theme in style.theme_names():
            style.theme_use(theme)
            break

    app = NetcheckApp(root)
    if argv:
        app.target_var.set(argv[0])
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())


