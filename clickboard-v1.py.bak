#!/usr/bin/env python3
"""
clickboard.py — a manually-launched tray app for bidirectional
clipboard sync between machines over SSH.

Click a machine in the tray menu to CONNECT it (or disconnect if
already connected). While connected, clipboard changes on either
machine are pushed to the other automatically — no further clicking
needed. Nothing syncs until you've explicitly connected that machine.

Tray icon: orange = no machines connected, green = at least one is.

Tested platform: Ubuntu 24.04 <-> Ubuntu 24.04 (xclip on both ends).

Requirements (pip install -r requirements.txt):
  pystray, pillow, pyperclip, paramiko
(everything else used — urllib, secrets, hashlib, subprocess — is
stdlib, so the pairing feature adds no new dependencies)

SSH setup: use "Test connection" in Configure to check a machine, or
"Pair devices..." to exchange SSH keys automatically via a small
self-hosted broker (see clickboard-pair.php) instead of manually
running ssh-copy-id on both ends.
"""

import base64
import hashlib
import json
import queue
import secrets
import socket
import sys
import getpass
import subprocess
import threading
import time
import tkinter as tk
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict, field
from pathlib import Path
from tkinter import ttk, messagebox

import paramiko
import pyperclip
import pystray
from PIL import Image, ImageDraw

CONFIG_DIR = Path.home() / ".config" / "clickboard"
CONFIG_FILE = CONFIG_DIR / "config.json"
SSH_DIR = Path.home() / ".ssh"
SSH_KEY_PATH = SSH_DIR / "id_ed25519"

# Placeholder — point this at wherever you deploy clickboard-pair.php.
DEFAULT_PAIRING_API_URL = "https://api.tiny-web.uk/pair.php"

def _migrate_api_url(url: str) -> str:
    """Upgrade configs saved with the old placeholder broker URL."""
    if not url or "clickboard-pair.php" in url or "pair.tiny-web.uk" in url:
        return DEFAULT_PAIRING_API_URL
    return url

# Commands run over SSH don't know about the desktop session, so find it:
# X11 socket + Xauthority, or the Wayland socket.
REMOTE_ENV = r"""
export XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
if [ -z "$WAYLAND_DISPLAY" ]; then
  w=$(ls "$XDG_RUNTIME_DIR" 2>/dev/null | grep -m1 '^wayland-[0-9]*$')
  [ -n "$w" ] && export WAYLAND_DISPLAY=$w
fi
if [ -z "$DISPLAY" ]; then
  x=$(ls /tmp/.X11-unix 2>/dev/null | sed -n 's/^X//p' | head -1)
  [ -n "$x" ] && export DISPLAY=:$x
fi
if [ -z "$XAUTHORITY" ]; then
  for f in "$XDG_RUNTIME_DIR"/gdm/Xauthority "$XDG_RUNTIME_DIR"/.mutter-Xwaylandauth.* "$HOME/.Xauthority"; do
    [ -f "$f" ] && export XAUTHORITY=$f && break
  done
fi
"""

REMOTE_GET_SCRIPT = r"""
set -e
if command -v xclip >/dev/null 2>&1; then
  xclip -selection clipboard -o 2>/dev/null | base64 -w0
elif command -v xsel >/dev/null 2>&1; then
  xsel --clipboard --output 2>/dev/null | base64 -w0
elif command -v wl-paste >/dev/null 2>&1; then
  wl-paste 2>/dev/null | base64 -w0
elif command -v powershell.exe >/dev/null 2>&1; then
  powershell.exe -NoProfile -Command Get-Clipboard 2>/dev/null | tr -d '\r' | base64 -w0
else
  echo "clickboard: no clipboard tool found on remote" >&2
  exit 1
fi
"""

REMOTE_SET_SCRIPT = r"""
set -e
if command -v xclip >/dev/null 2>&1; then
  base64 -d | xclip -selection clipboard -i
elif command -v xsel >/dev/null 2>&1; then
  base64 -d | xsel --clipboard --input
elif command -v wl-copy >/dev/null 2>&1; then
  base64 -d | wl-copy
elif command -v clip.exe >/dev/null 2>&1; then
  base64 -d | clip.exe
else
  echo "clickboard: no clipboard tool found on remote" >&2
  exit 1
fi
"""


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

@dataclass
class MachineConfig:
    name: str
    host: str
    user: str
    port: int = 22
    key_path: str = ""


@dataclass
class AppConfig:
    machines: list = field(default_factory=list)
    poll_interval: float = 1.0
    pairing_api_url: str = DEFAULT_PAIRING_API_URL

    @staticmethod
    def load():
        if CONFIG_FILE.exists():
            raw = json.loads(CONFIG_FILE.read_text())
            machines = [MachineConfig(**m) for m in raw.get("machines", [])]
            return AppConfig(
                machines=machines,
                poll_interval=raw.get("poll_interval", 1.0),
                pairing_api_url=_migrate_api_url(raw.get("pairing_api_url", DEFAULT_PAIRING_API_URL)),
            )
        return AppConfig()

    def save(self):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        data = {
            "machines": [asdict(m) for m in self.machines],
            "poll_interval": self.poll_interval,
            "pairing_api_url": self.pairing_api_url,
        }
        CONFIG_FILE.write_text(json.dumps(data, indent=2))


def ssh_connect_kwargs(cfg: MachineConfig, timeout=6):
    kwargs = dict(
        hostname=cfg.host,
        port=cfg.port,
        username=cfg.user,
        timeout=timeout,
        banner_timeout=timeout,
        look_for_keys=True,
        allow_agent=True,
    )
    if cfg.key_path:
        kwargs["key_filename"] = cfg.key_path
    return kwargs


def ssh_setup_steps(cfg: MachineConfig, error: str):
    """Structured setup steps (description, command) so the UI can
    render each one individually copyable, rather than one text blob."""
    header = (
        f"Couldn't connect to {cfg.user}@{cfg.host}:{cfg.port}.\n\n"
        f"Error: {error}\n\n"
        "Follow these steps, then remember Clickboard needs this "
        f"working in BOTH directions — repeat on {cfg.host}, pointing "
        "back at this machine, too. (Or use \"Pair devices...\" instead "
        "to do both directions automatically.)"
    )
    steps = [
        ("Generate a key on THIS machine, if you don't already have one:",
         "ssh-keygen -t ed25519"),
        ("Copy your public key to the remote machine:",
         f"ssh-copy-id -p {cfg.port} {cfg.user}@{cfg.host}"),
        ("Test it manually:",
         f"ssh -p {cfg.port} {cfg.user}@{cfg.host}"),
    ]
    return header, steps


# --------------------------------------------------------------------------
# Keypair + pairing helpers
# --------------------------------------------------------------------------

def ensure_local_keypair() -> Path:
    """Returns the path to a local ed25519 private key, generating a
    passphrase-less one if none exists yet (needed for the automated
    sync loop to connect without a human typing a passphrase each
    time — consistent with the rest of the app's passwordless-SSH
    assumption)."""
    if SSH_KEY_PATH.exists():
        return SSH_KEY_PATH
    SSH_DIR.mkdir(mode=0o700, exist_ok=True)
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", str(SSH_KEY_PATH), "-N", ""],
        check=True, capture_output=True,
    )
    return SSH_KEY_PATH


def read_local_pubkey() -> str:
    pub_path = SSH_KEY_PATH.with_suffix(".pub")
    return pub_path.read_text().strip()


def key_fingerprint(pubkey_line: str) -> str:
    """OpenSSH-style SHA256 fingerprint, e.g. 'SHA256:abcd...' — the
    same format `ssh-keygen -lf` prints, so it's recognisable."""
    parts = pubkey_line.strip().split()
    if len(parts) < 2:
        return "(unrecognised key format)"
    key_bytes = base64.b64decode(parts[1])
    digest = hashlib.sha256(key_bytes).digest()
    b64 = base64.b64encode(digest).decode().rstrip("=")
    return f"SHA256:{b64}"


def add_to_authorized_keys(pubkey_line: str) -> bool:
    """Appends a key to ~/.ssh/authorized_keys if not already present.
    Returns True if it was added, False if it was already there."""
    auth_path = SSH_DIR / "authorized_keys"
    SSH_DIR.mkdir(mode=0o700, exist_ok=True)
    existing = auth_path.read_text() if auth_path.exists() else ""
    key_material = pubkey_line.strip().split()[1] if len(pubkey_line.split()) >= 2 else pubkey_line
    if key_material in existing:
        return False
    with open(auth_path, "a") as f:
        if existing and not existing.endswith("\n"):
            f.write("\n")
        f.write(pubkey_line.strip() + "\n")
    auth_path.chmod(0o600)
    return True


def pairing_post(api_url: str, code: str, label: str, pubkey: str, timeout=8) -> dict:
    body = json.dumps({"code": code, "label": label, "pubkey": pubkey}).encode()
    req = urllib.request.Request(api_url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def pairing_get(api_url: str, code: str, timeout=8) -> dict:
    url = f"{api_url}?code={urllib.parse.quote(code)}"
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def generate_pairing_code() -> str:
    return secrets.token_hex(5).upper()  # 10 hex chars, e.g. "3F9A0B21CE"


# --------------------------------------------------------------------------
# Per-machine connection worker (continuous sync while connected)
# --------------------------------------------------------------------------

class MachineWorker:
    def __init__(self, cfg: MachineConfig, poll_interval: float, on_status_change):
        self.cfg = cfg
        self.poll_interval = poll_interval
        self.on_status_change = on_status_change
        self._client = None
        self._thread = None
        self._stop = threading.Event()
        self.connected = False
        self.last_error = ""
        self._last_local = ""
        self._last_remote = ""

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
        self._set_connected(False)

    def is_running(self):
        return bool(self._thread and self._thread.is_alive())

    def _set_connected(self, value: bool):
        if value != self.connected:
            self.connected = value
            self.on_status_change(self.cfg.name, value)

    def _connect(self):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(**ssh_connect_kwargs(self.cfg))
        transport = client.get_transport()
        transport.set_keepalive(5)
        self._client = client

    def _remote_exec(self, script: str, stdin_data: bytes = None) -> bytes:
        stdin, stdout, stderr = self._client.exec_command(REMOTE_ENV + script, timeout=8)
        if stdin_data is not None:
            stdin.write(stdin_data)
            stdin.channel.shutdown_write()
        out = stdout.read()
        err = stderr.read()
        if err and not out:
            self.last_error = err.decode(errors="replace").strip()
            print(f"[clickboard] {self.cfg.name}: remote error: {self.last_error}", file=sys.stderr, flush=True)
        return out

    def _run(self):
        backoff = 1
        max_backoff = 30
        while not self._stop.is_set():
            try:
                self._connect()
                self._set_connected(True)
                self.last_error = ""
                backoff = 1

                while not self._stop.is_set():
                    try:
                        local_val = pyperclip.paste()
                    except Exception:
                        local_val = self._last_local

                    if local_val and local_val != self._last_local and local_val != self._last_remote:
                        encoded = base64.b64encode(local_val.encode()).decode()
                        self._remote_exec(REMOTE_SET_SCRIPT, (encoded + "\n").encode())
                        self._last_local = local_val

                    remote_out = self._remote_exec(REMOTE_GET_SCRIPT)
                    if remote_out:
                        try:
                            remote_val = base64.b64decode(remote_out).decode(errors="replace")
                        except Exception:
                            remote_val = ""
                        if remote_val and remote_val != self._last_remote and remote_val != self._last_local:
                            pyperclip.copy(remote_val)
                            self._last_remote = remote_val
                            self._last_local = remote_val

                    time.sleep(self.poll_interval)

            except Exception as exc:
                self.last_error = str(exc)
                print(f"[clickboard] {self.cfg.name}: {exc}", file=sys.stderr, flush=True)
                self._set_connected(False)
                if self._stop.is_set():
                    break
                time.sleep(backoff)
                backoff = min(backoff * 2, max_backoff)

        self._set_connected(False)


# --------------------------------------------------------------------------
# Tray application
# --------------------------------------------------------------------------

class TrayApp:
    def __init__(self):
        self.config = AppConfig.load()
        self.workers = {}
        self._rebuild_workers()
        self._config_lock = threading.Lock()
        self._config_open = False

        self.icon = pystray.Icon(
            "clickboard",
            icon=self._make_icon("orange"),
            title="clickboard (idle)",
            menu=pystray.Menu(self._build_menu),
        )

    def _rebuild_workers(self):
        existing = set(self.workers)
        wanted = set(m.name for m in self.config.machines)
        for name in existing - wanted:
            self.workers[name].stop()
            del self.workers[name]
        for m in self.config.machines:
            if m.name not in self.workers:
                self.workers[m.name] = MachineWorker(m, self.config.poll_interval, self._on_status_change)
            else:
                self.workers[m.name].cfg = m

    def _on_status_change(self, name, connected):
        self._refresh_icon()

    def _make_icon(self, color: str) -> Image.Image:
        size = 64
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        pad = 4
        draw.ellipse([pad, pad, size - pad, size - pad], fill=color)
        return img

    def _refresh_icon(self):
        any_connected = any(w.connected for w in self.workers.values())
        self.icon.icon = self._make_icon("green" if any_connected else "orange")
        n = sum(1 for w in self.workers.values() if w.connected)
        self.icon.title = f"clickboard ({n} connected)" if n else "clickboard (idle)"

    def _build_menu(self):
        n_connected = sum(1 for w in self.workers.values() if w.connected)
        items = [
            pystray.MenuItem(f"Status: {n_connected} connected", None, enabled=False),
            pystray.Menu.SEPARATOR,
        ]
        if not self.workers:
            items.append(pystray.MenuItem("No machines configured", None, enabled=False))
        else:
            for name, worker in self.workers.items():
                dot = "\u25cf" if worker.connected else "\u25cb"
                label = f"{dot} {name} ({worker.cfg.host})"
                items.append(pystray.MenuItem(label, self._make_toggle(name)))
        items.append(pystray.Menu.SEPARATOR)
        items.append(pystray.MenuItem("Reconnect all", self._reconnect_all))
        items.append(pystray.MenuItem("Configure...", self._request_config_window))
        items.append(pystray.Menu.SEPARATOR)
        items.append(pystray.MenuItem("Quit", self._quit))
        return items

    def _make_toggle(self, name):
        def toggle(icon, item):
            worker = self.workers[name]
            if worker.is_running():
                worker.stop()
            else:
                worker.start()
            self._refresh_icon()
        return toggle

    def _reconnect_all(self, icon, item):
        for worker in self.workers.values():
            worker.stop()
        for worker in self.workers.values():
            worker.start()

    def _quit(self, icon, item):
        for worker in self.workers.values():
            worker.stop()
        icon.stop()

    # -- config window ---------------------------------------------------

    def _request_config_window(self, icon, item):
        with self._config_lock:
            if self._config_open:
                return
            self._config_open = True
        threading.Thread(target=self._run_config_window, daemon=True).start()

    def _run_config_window(self):
        try:
            root = tk.Tk()
            def _edit_menu(event):
                w = event.widget
                m = tk.Menu(w, tearoff=0)
                m.add_command(label="Cut", command=lambda: w.event_generate("<<Cut>>"))
                m.add_command(label="Copy", command=lambda: w.event_generate("<<Copy>>"))
                m.add_command(label="Paste", command=lambda: w.event_generate("<<Paste>>"))
                m.add_separator()
                m.add_command(label="Select all", command=lambda: w.select_range(0, "end"))
                w.focus_set()
                m.tk_popup(event.x_root, event.y_root)
            root.bind_class("TEntry", "<Button-3>", _edit_menu)
            root.bind_class("Entry", "<Button-3>", _edit_menu)
            root.title("clickboard \u2014 configure machines")
            self._build_config_ui(root)
            root.update_idletasks()
            root.minsize(root.winfo_width(), root.winfo_height())
            root.lift()
            root.attributes("-topmost", True)
            root.after(300, lambda: root.attributes("-topmost", False))
            root.after(100, root.focus_force)
            root.mainloop()
        finally:
            with self._config_lock:
                self._config_open = False

    def _build_config_ui(self, win):
        # Pairing API URL, editable so it's not hardcoded per deployment.
        api_frame = ttk.Frame(win)
        api_frame.pack(fill="x", padx=10, pady=(10, 0))
        ttk.Label(api_frame, text="Pairing API URL:").pack(side="left")
        api_entry = ttk.Entry(api_frame, width=45)
        api_entry.insert(0, self.config.pairing_api_url)
        api_entry.pack(side="left", padx=5, fill="x", expand=True)

        def save_api_url():
            self.config.pairing_api_url = api_entry.get().strip()
            self.config.save()

        api_entry.bind("<FocusOut>", lambda e: save_api_url())

        listbox = tk.Listbox(win, height=8)
        listbox.pack(fill="both", expand=True, padx=10, pady=(10, 5))
        for m in self.config.machines:
            listbox.insert("end", f"{m.name}  \u2014  {m.user}@{m.host}:{m.port}")

        form = ttk.Frame(win)
        form.pack(fill="x", padx=10, pady=5)

        fields = {}
        for i, label in enumerate(["Name", "Host", "User", "Port", "Key path (optional)"]):
            ttk.Label(form, text=label).grid(row=i, column=0, sticky="w")
            entry = ttk.Entry(form, width=32)
            entry.grid(row=i, column=1, sticky="w", pady=2)
            fields[label] = entry
        fields["Port"].insert(0, "22")

        def load_selected(_event=None):
            sel = listbox.curselection()
            if not sel:
                return
            m = self.config.machines[sel[0]]
            fields["Name"].delete(0, "end"); fields["Name"].insert(0, m.name)
            fields["Host"].delete(0, "end"); fields["Host"].insert(0, m.host)
            fields["User"].delete(0, "end"); fields["User"].insert(0, m.user)
            fields["Port"].delete(0, "end"); fields["Port"].insert(0, str(m.port))
            fields["Key path (optional)"].delete(0, "end"); fields["Key path (optional)"].insert(0, m.key_path)

        listbox.bind("<<ListboxSelect>>", load_selected)

        def current_form_cfg():
            name = fields["Name"].get().strip() or "(test)"
            host = fields["Host"].get().strip()
            user = fields["User"].get().strip()
            port_str = fields["Port"].get().strip() or "22"
            key_path = fields["Key path (optional)"].get().strip()
            try:
                port = int(port_str)
            except ValueError:
                port = 22
            return MachineConfig(name, host, user, port, key_path)

        def test_connection():
            cfg = current_form_cfg()
            if not (cfg.host and cfg.user):
                messagebox.showerror("clickboard", "Enter at least Host and User before testing.")
                return
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(**ssh_connect_kwargs(cfg, timeout=6))
                stdin, stdout, stderr = client.exec_command("echo ok", timeout=6)
                out = stdout.read().decode(errors="replace").strip()
                client.close()
                if out == "ok":
                    messagebox.showinfo("clickboard", f"Connected successfully to {cfg.user}@{cfg.host}:{cfg.port}.")
                else:
                    messagebox.showwarning("clickboard", f"Connected, but got unexpected output: {out!r}")
            except Exception as exc:
                header, steps = ssh_setup_steps(cfg, str(exc))
                show_help_dialog(win, "clickboard \u2014 connection failed", header, steps)

        def add_or_update():
            cfg = current_form_cfg()
            if not (cfg.host and cfg.user and fields["Name"].get().strip()):
                messagebox.showerror("clickboard", "Name, host and user are required.")
                return
            existing_names = [m.name for m in self.config.machines]
            if cfg.name in existing_names:
                self.config.machines[existing_names.index(cfg.name)] = cfg
            else:
                self.config.machines.append(cfg)
            self.config.save()
            self._rebuild_workers()
            self._refresh_icon()
            refresh_listbox()

        def remove_selected():
            sel = listbox.curselection()
            if not sel:
                return
            m = self.config.machines.pop(sel[0])
            if m.name in self.workers:
                self.workers[m.name].stop()
                del self.workers[m.name]
            self.config.save()
            self._refresh_icon()
            refresh_listbox()

        def refresh_listbox():
            listbox.delete(0, "end")
            for m in self.config.machines:
                listbox.insert("end", f"{m.name}  \u2014  {m.user}@{m.host}:{m.port}")

        def add_paired(label):
            user, _, host = label.partition("@")
            if not host:  # older peer sent only a hostname
                user, host = getpass.getuser(), label
            short = host.split(".")[0]
            cfg = MachineConfig(name=short, host=f"{short}.local", user=user)
            names = [m.name for m in self.config.machines]
            if short in names:
                self.config.machines[names.index(short)] = cfg
            else:
                self.config.machines.append(cfg)
            self.config.save()
            self._rebuild_workers()
            self._refresh_icon()
            refresh_listbox()

        def open_pairing():
            open_pairing_dialog(win, self.config.pairing_api_url, on_paired=add_paired)

        btns = ttk.Frame(win)
        btns.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(btns, text="Test connection", command=test_connection).pack(side="left")
        ttk.Button(btns, text="Pair devices...", command=open_pairing).pack(side="left", padx=5)
        ttk.Button(btns, text="Add / Update", command=add_or_update).pack(side="left", padx=5)
        ttk.Button(btns, text="Remove selected", command=remove_selected).pack(side="left")
        ttk.Button(btns, text="Close", command=win.destroy).pack(side="right")

    def run(self):
        self.icon.run()


# --------------------------------------------------------------------------
# Selectable, individually-copyable SSH help dialog
# --------------------------------------------------------------------------

def _copy_to_clipboard(widget, text):
    widget.clipboard_clear()
    widget.clipboard_append(text)
    widget.update()


def show_help_dialog(parent, title, header_text, steps):
    """steps: list of (description, command) tuples, each rendered
    with its own Copy button. header_text is shown in a plain
    selectable Text widget (not a locked-down messagebox label)."""
    win = tk.Toplevel(parent)
    win.title(title)

    outer = ttk.Frame(win, padding=14)
    outer.pack(fill="both", expand=True)

    header = tk.Text(outer, wrap="word", height=6, relief="flat",
                      background=win.cget("background"), borderwidth=0)
    header.insert("1.0", header_text)
    header.configure(state="normal")  # stays selectable/copyable
    header.pack(fill="x", pady=(0, 12))

    for desc, cmd in steps:
        step_frame = ttk.Frame(outer)
        step_frame.pack(fill="x", pady=6)
        ttk.Label(step_frame, text=desc, wraplength=520, justify="left").pack(anchor="w")

        row = ttk.Frame(step_frame)
        row.pack(fill="x", pady=(3, 0))
        cmd_entry = tk.Entry(row, font=("monospace", 10))
        cmd_entry.insert(0, cmd)
        cmd_entry.configure(state="readonly", readonlybackground="white")
        cmd_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Copy", width=8,
                   command=lambda c=cmd: _copy_to_clipboard(win, c)).pack(side="left", padx=(6, 0))

    ttk.Button(outer, text="Close", command=win.destroy).pack(anchor="e", pady=(10, 0))

    win.update_idletasks()
    # 50% wider than a plain messagebox would be, and only as tall as
    # the content needs — wide-and-short rather than narrow-and-long.
    natural_w = max(win.winfo_width(), 600)
    win.geometry(f"{int(natural_w * 1.0)}x{win.winfo_height()}")
    win.minsize(natural_w, win.winfo_height())


# --------------------------------------------------------------------------
# Pairing dialog
# --------------------------------------------------------------------------

def open_pairing_dialog(parent, api_url, on_paired=None):
    win = tk.Toplevel(parent)
    win.title("clickboard \u2014 pair devices")
    outer = ttk.Frame(win, padding=14)
    outer.pack(fill="both", expand=True)

    ttk.Label(outer, text=(
        "Generates an SSH key on this machine if needed, then exchanges "
        "public keys with another machine via a short-lived pairing code. "
        "Run this on BOTH machines with the SAME code."
    ), wraplength=480, justify="left").pack(anchor="w", pady=(0, 10))

    code_frame = ttk.Frame(outer)
    code_frame.pack(fill="x", pady=(0, 10))
    ttk.Label(code_frame, text="Pairing code:").pack(side="left")
    code_var = tk.StringVar(value=generate_pairing_code())
    code_entry = ttk.Entry(code_frame, textvariable=code_var, font=("monospace", 12), width=16)
    code_entry.pack(side="left", padx=6)
    ttk.Button(code_frame, text="New code", command=lambda: code_var.set(generate_pairing_code())).pack(side="left")
    ttk.Button(code_frame, text="Copy", command=lambda: _copy_to_clipboard(win, code_var.get())).pack(side="left", padx=4)

    status_var = tk.StringVar(value="Enter/confirm the code, then click Start on both machines.")
    status_label = ttk.Label(outer, textvariable=status_var, wraplength=480, justify="left")
    status_label.pack(anchor="w", fill="x", pady=(0, 10))

    stop_flag = threading.Event()

    def do_pair():
        code = code_var.get().strip()
        if not code:
            status_var.set("Enter a pairing code first.")
            return
        try:
            key_path = ensure_local_keypair()
        except Exception as exc:
            status_var.set(f"Couldn't generate/find a local SSH key: {exc}")
            return

        pubkey = read_local_pubkey()
        label = f"{getpass.getuser()}@{socket.gethostname()}"

        try:
            pairing_post(api_url, code, label, pubkey)
        except Exception as exc:
            status_var.set(f"Couldn't reach pairing API at {api_url}: {exc}")
            return

        status_var.set(f"Waiting for the other machine to join with code {code}...")
        stop_flag.clear()
        threading.Thread(target=poll_loop, args=(code, label), daemon=True).start()

    def poll_loop(code, my_label):
        deadline = time.time() + 300  # 5 minutes
        while time.time() < deadline and not stop_flag.is_set():
            try:
                result = pairing_get(api_url, code)
                entries = result.get("entries", [])
                other = next((e for e in entries if e["label"] != my_label), None)
                if other:
                    win.after(0, lambda: show_confirm(other))
                    return
            except Exception:
                pass
            time.sleep(2)
        if not stop_flag.is_set():
            win.after(0, lambda: status_var.set("Timed out waiting for the other machine. Try a new code."))

    def show_confirm(other):
        fp = key_fingerprint(other["pubkey"])
        status_var.set(
            f"Found a machine calling itself \"{other['label']}\".\n\n"
            f"Fingerprint: {fp}\n\n"
            f"Check this matches what's shown on {other['label']}'s screen, "
            "then click Trust and add below."
        )

        def trust_and_add():
            added = add_to_authorized_keys(other["pubkey"])
            if on_paired:
                on_paired(other["label"])
            status_var.set(
                ("Added" if added else "Already present —")
                + f" {other['label']}'s key is now authorized on this machine."
            )
            trust_btn.pack_forget()

        trust_btn = ttk.Button(outer, text="Trust and add", command=trust_and_add)
        trust_btn.pack(anchor="w", pady=(0, 10))

    btns = ttk.Frame(outer)
    btns.pack(fill="x")
    ttk.Button(btns, text="Start pairing", command=lambda: threading.Thread(target=do_pair, daemon=True).start()).pack(side="left")
    ttk.Button(btns, text="Close", command=lambda: (stop_flag.set(), win.destroy())).pack(side="right")

    win.update_idletasks()
    win.minsize(max(win.winfo_width(), 560), win.winfo_height())


if __name__ == "__main__":
    TrayApp().run()
