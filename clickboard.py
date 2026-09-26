#!/usr/bin/env python3
"""
Clickboard - the clipboard that follows you between machines.

Sign in with your Tiny-Web API key on each machine. Machines on the same
account find each other through the Tiny-Web API, then connect directly
over the local network using mutual TLS: each machine only trusts the
certificates registered to its own account, so other people on the same
Wi-Fi can't connect. Clipboard contents go machine to machine and never
touch the server.
"""
import datetime
import hashlib
import json
import os
import platform
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
import webbrowser
from pathlib import Path

import pyperclip
import pystray
from PIL import Image, ImageDraw
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

VERSION = "2.0.0"
API_BASE = "https://tiny-web.uk/api/"
SIGNUP_URL = "https://clickboard.eur.bz/#signup"
DEFAULT_PORT = 47800
REGISTER_EVERY = 60       # seconds between check-ins with Tiny-Web
DIAL_EVERY = 5            # seconds between attempts to reach unconnected machines
POLL_EVERY = 0.4          # seconds between local clipboard checks
PING_EVERY = 20           # keepalive; a link silent for 3x this is dropped
MAX_CLIP_BYTES = 10 * 1024 * 1024

if platform.system() == "Windows":
    CONFIG_DIR = Path(os.environ.get("APPDATA", str(Path.home()))) / "Clickboard"
else:
    CONFIG_DIR = Path.home() / ".config" / "clickboard"
CONFIG_FILE = CONFIG_DIR / "config.json"
CERT_FILE = CONFIG_DIR / "cert.pem"
KEY_FILE = CONFIG_DIR / "key.pem"

COLOUR_OK = (13, 148, 136, 255)       # teal: at least one machine connected
COLOUR_IDLE = (140, 140, 140, 255)    # grey: nothing connected yet
COLOUR_WARN = (217, 119, 6, 255)      # amber: needs attention (no key, error)


def log(msg):
    print(f"[clickboard {time.strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


# -- Config ------------------------------------------------------------------

class Config:
    FIELDS = ("api_key", "device_id", "name", "port", "paused")

    def __init__(self):
        self.api_key = ""
        self.device_id = str(uuid.uuid4())
        self.name = "".join(c for c in socket.gethostname().split(".")[0] if c.isalnum() or c in " .-_")[:64] or "machine"
        self.port = DEFAULT_PORT
        self.paused = False

    @classmethod
    def load(cls):
        cfg = cls()
        if CONFIG_FILE.exists():
            try:
                raw = json.loads(CONFIG_FILE.read_text())
                for k in cls.FIELDS:
                    if k in raw:
                        setattr(cfg, k, raw[k])
            except Exception as exc:
                log(f"config unreadable, starting fresh: {exc}")
        cfg.save()
        return cfg

    def save(self):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(json.dumps({k: getattr(self, k) for k in self.FIELDS}, indent=2))
        try:
            os.chmod(CONFIG_FILE, 0o600)
        except OSError:
            pass


# -- Identity: a self-signed certificate per machine -------------------------

def ensure_identity(device_id: str) -> str:
    """Create this machine's TLS certificate on first run; return it as PEM."""
    if CERT_FILE.exists() and KEY_FILE.exists():
        return CERT_FILE.read_text()
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"clickboard-{device_id}")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        # Self-signed and marked as its own CA, so a sibling can load it
        # directly as a trust anchor for mutual TLS.
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    KEY_FILE.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    try:
        os.chmod(KEY_FILE, 0o600)
    except OSError:
        pass
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    CERT_FILE.write_text(pem)
    log("created this machine's certificate")
    return pem


def der_fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def lan_addrs() -> list:
    addrs = set()
    try:
        # Connecting a UDP socket sends nothing; it just picks the outgoing interface.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))
        addrs.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127."):
                addrs.add(ip)
    except OSError:
        pass
    return sorted(addrs)


# -- Tiny-Web API ------------------------------------------------------------

def api_post(endpoint: str, api_key: str, payload: dict, timeout=10) -> dict:
    req = urllib.request.Request(
        API_BASE + endpoint,
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": f"Clickboard/{VERSION}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as exc:
        try:
            return json.loads(exc.read())
        except Exception:
            return {"ok": False, "error": f"Tiny-Web returned HTTP {exc.code}"}
    except Exception as exc:
        return {"ok": False, "error": f"Can't reach Tiny-Web: {exc}"}


# -- Wire protocol: [4-byte header length][JSON header][payload bytes] -------

def recv_exact(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return bytes(buf)


def recv_frame(sock):
    (hlen,) = struct.unpack(">I", recv_exact(sock, 4))
    if hlen > 65536:
        raise ValueError("header too large")
    header = json.loads(recv_exact(sock, hlen))
    size = int(header.get("size", 0))
    if size < 0 or size > MAX_CLIP_BYTES:
        raise ValueError("payload too large")
    return header, (recv_exact(sock, size) if size else b"")


class Link:
    """One live TLS connection to a sibling machine."""

    def __init__(self, app, sock, peer_id: str, initiator: str):
        self.app = app
        self.sock = sock
        self.peer_id = peer_id
        self.initiator = initiator
        self.alive = True
        self._send_lock = threading.Lock()

    def send(self, header: dict, payload: bytes = b""):
        header = dict(header, size=len(payload))
        h = json.dumps(header).encode()
        try:
            with self._send_lock:
                self.sock.sendall(struct.pack(">I", len(h)) + h + payload)
        except Exception as exc:
            self.close(f"send failed: {exc}")

    def run(self):
        self.sock.settimeout(PING_EVERY * 3)
        try:
            while self.alive:
                header, payload = recv_frame(self.sock)
                if header.get("type") == "clip":
                    self.app.on_remote_clip(self.peer_id, header, payload)
        except Exception as exc:
            self.close(str(exc))

    def close(self, why: str = ""):
        if not self.alive:
            return
        self.alive = False
        try:
            self.sock.close()
        except Exception:
            pass
        self.app.on_link_closed(self, why)


# -- The app -----------------------------------------------------------------

class App:
    def __init__(self):
        self.cfg = Config.load()
        self.cert_pem = ensure_identity(self.cfg.device_id)
        self.running = True
        self.lock = threading.Lock()
        self.peers = {}            # device_id -> device dict from Tiny-Web
        self.peers_loaded = False
        self.links = {}            # device_id -> Link
        self.plan = None
        self.status = ""
        self.warn = False
        self.last_clip = None
        self.clip_lock = threading.Lock()
        self.wake = threading.Event()
        self._last_wake = 0.0
        self.icon = None
        self._settings_open = False
        self._build_contexts()

    # TLS contexts: trust exactly the certificates registered to this account
    def _build_contexts(self):
        pems = [p["cert_pem"] for p in self.peers.values() if p.get("cert_pem")]
        srv = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cli = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cli.check_hostname = False   # identity is the pinned certificate, not a hostname
        for ctx in (srv, cli):
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.load_cert_chain(str(CERT_FILE), str(KEY_FILE))
            ctx.verify_mode = ssl.CERT_REQUIRED
            if pems:
                ctx.load_verify_locations(cadata="\n".join(pems))
        self.srv_ctx, self.cli_ctx = srv, cli

    # ---- registration / discovery ----
    def register_loop(self):
        while self.running:
            self.register_now()
            self.wake.wait(REGISTER_EVERY)
            self.wake.clear()

    def poke_register(self):
        """Ask for an early check-in (rate-limited), e.g. when an unknown machine knocks."""
        if time.time() - self._last_wake > 10:
            self._last_wake = time.time()
            self.wake.set()

    def register_now(self):
        if not self.cfg.api_key:
            self.set_status("Add your Tiny-Web key in Settings", warn=True)
            return
        r = api_post("clickboard-register.php", self.cfg.api_key, {
            "device_id": self.cfg.device_id,
            "name": self.cfg.name,
            "platform": {"Windows": "windows", "Darwin": "macos"}.get(platform.system(), "linux"),
            "lan_addrs": lan_addrs(),
            "port": self.cfg.port,
            "cert_pem": self.cert_pem,
        })
        if not r.get("ok"):
            self.set_status(r.get("error", "Registration failed"), warn=True)
            return
        self.plan = r.get("plan")
        fresh = {d["device_id"]: d for d in r.get("devices", [])}
        joined = [d for pid, d in fresh.items() if pid not in self.peers] if self.peers_loaded else []
        gone = [pid for pid in self.peers if pid not in fresh]
        certs_changed = {p.get("cert_fp") for p in fresh.values()} != {p.get("cert_fp") for p in self.peers.values()}
        self.peers = fresh
        self.peers_loaded = True
        if certs_changed:
            self._build_contexts()
        for pid in gone:
            link = self.links.get(pid)
            if link:
                link.close("removed from account")
        for d in joined:
            self.notify(f"{d['name']} joined your Clickboard. Not yours? Remove it in Settings.")
        self.set_status("")

    # ---- TLS server ----
    def serve(self):
        try:
            ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ls.bind(("0.0.0.0", self.cfg.port))
            ls.listen(8)
        except OSError as exc:
            self.set_status(f"Can't listen on port {self.cfg.port} (is Clickboard already running?)", warn=True)
            log(f"listen failed: {exc}")
            return
        log(f"listening on port {self.cfg.port}")
        while self.running:
            try:
                conn, addr = ls.accept()
            except OSError:
                continue
            threading.Thread(target=self._accept, args=(conn, addr), daemon=True).start()

    def _accept(self, conn, addr):
        try:
            conn.settimeout(10)
            tls = self.srv_ctx.wrap_socket(conn, server_side=True)
            self._adopt(tls, initiated_by_me=False)
        except Exception as exc:
            log(f"refused connection from {addr[0]}: {exc}")
            try:
                conn.close()
            except Exception:
                pass
            # Possibly a sibling that registered after our last check-in.
            self.poke_register()

    # ---- dialling siblings ----
    def dial_loop(self):
        while self.running:
            for pid, peer in list(self.peers.items()):
                if not self.running:
                    break
                link = self.links.get(pid)
                if (link and link.alive) or not peer.get("online") or not peer.get("cert_pem") or not peer.get("port"):
                    continue
                for addr in peer.get("lan_addrs", []):
                    try:
                        sock = socket.create_connection((addr, peer["port"]), timeout=3)
                        tls = self.cli_ctx.wrap_socket(sock)
                        self._adopt(tls, initiated_by_me=True)
                        break
                    except Exception:
                        continue
            time.sleep(DIAL_EVERY)

    def _adopt(self, tls, initiated_by_me: bool):
        fp = der_fingerprint(tls.getpeercert(binary_form=True))
        peer = next((p for p in self.peers.values() if p.get("cert_fp") == fp), None)
        if not peer:
            tls.close()
            return
        pid = peer["device_id"]
        link = Link(self, tls, pid, self.cfg.device_id if initiated_by_me else pid)
        preferred = min(self.cfg.device_id, pid)   # both sides agree which duplicate survives
        replaced = None
        with self.lock:
            old = self.links.get(pid)
            if old and old.alive:
                if old.initiator == preferred or link.initiator != preferred:
                    tls.close()
                    return
                replaced = old
            self.links[pid] = link
        if replaced:
            replaced.close("replaced by preferred connection")
        threading.Thread(target=link.run, daemon=True).start()
        log(f"connected to {peer['name']}")
        self.refresh_ui()

    def on_link_closed(self, link, why):
        with self.lock:
            if self.links.get(link.peer_id) is link:
                del self.links[link.peer_id]
        name = self.peers.get(link.peer_id, {}).get("name", link.peer_id[:8])
        log(f"disconnected from {name}: {why}")
        self.refresh_ui()

    def ping_loop(self):
        while self.running:
            time.sleep(PING_EVERY)
            for link in list(self.links.values()):
                link.send({"type": "ping"})

    # ---- clipboard ----
    def watch_clipboard(self):
        warned = False
        try:
            self.last_clip = pyperclip.paste()   # don't broadcast whatever was there at startup
        except Exception:
            pass
        while self.running:
            try:
                text = pyperclip.paste()
                warned = False
            except Exception as exc:
                if not warned:
                    log(f"can't read the clipboard: {exc}")
                    warned = True
                text = None
            if text is not None:
                with self.clip_lock:
                    changed = text != self.last_clip
                    if changed:
                        self.last_clip = text
                if changed and text and not self.cfg.paused:
                    self.broadcast_text(text)
            time.sleep(POLL_EVERY)

    def broadcast_text(self, text: str):
        data = text.encode("utf-8")
        if len(data) > MAX_CLIP_BYTES:
            log("clipboard too large to send")
            return
        for link in list(self.links.values()):
            link.send({"type": "clip", "mime": "text/plain;charset=utf-8"}, data)

    def on_remote_clip(self, peer_id, header, payload):
        if self.cfg.paused:
            return
        if str(header.get("mime", "")).startswith("text/plain"):
            text = payload.decode("utf-8", errors="replace")
            with self.clip_lock:
                self.last_clip = text   # so the watcher doesn't bounce it straight back
                try:
                    pyperclip.copy(text)
                except Exception as exc:
                    log(f"can't write the clipboard: {exc}")

    # ---- UI plumbing ----
    def set_status(self, text, warn=False):
        if text != self.status or warn != self.warn:
            self.status, self.warn = text, warn
            if text:
                log(text)
            self.refresh_ui()

    def notify(self, msg):
        log(msg)
        try:
            if shutil.which("notify-send"):
                subprocess.Popen(["notify-send", "Clickboard", msg])
            elif self.icon:
                self.icon.notify(msg, "Clickboard")
        except Exception:
            pass

    def connected_count(self):
        return sum(1 for link in self.links.values() if link.alive)

    def status_line(self):
        if self.status:
            return self.status
        if self.cfg.paused:
            return "Paused"
        n, total = self.connected_count(), len(self.peers)
        if total == 0:
            return "No other machines yet - install on another machine"
        return f"Syncing with {n} of {total} machine{'s' if total != 1 else ''}"

    def refresh_ui(self):
        if not self.icon:
            return
        colour = COLOUR_WARN if self.warn else (COLOUR_OK if self.connected_count() and not self.cfg.paused else COLOUR_IDLE)
        try:
            self.icon.icon = icon_image(colour)
            self.icon.title = f"Clickboard - {self.status_line()}"
            self.icon.update_menu()
        except Exception:
            pass

    def build_menu(self):
        items = [pystray.MenuItem(self.status_line(), None, enabled=False), pystray.Menu.SEPARATOR]
        for p in sorted(self.peers.values(), key=lambda d: d["name"].lower()):
            link = self.links.get(p["device_id"])
            mark = "\u25cf " if (link and link.alive) else "\u25cb "
            items.append(pystray.MenuItem(mark + p["name"], None, enabled=False))
        if self.peers:
            items.append(pystray.Menu.SEPARATOR)
        items += [
            pystray.MenuItem("Pause sync", self.toggle_pause, checked=lambda item: self.cfg.paused),
            pystray.MenuItem("Settings...", lambda: self.open_settings()),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", self.quit),
        ]
        return items

    def toggle_pause(self):
        self.cfg.paused = not self.cfg.paused
        self.cfg.save()
        self.refresh_ui()

    def quit(self):
        self.running = False
        for link in list(self.links.values()):
            link.close("quitting")
        if self.icon:
            self.icon.stop()

    def open_settings(self):
        if self._settings_open:
            return
        self._settings_open = True
        threading.Thread(target=self._settings_window, daemon=True).start()

    def _settings_window(self):
        try:
            SettingsWindow(self).run()
        except Exception as exc:
            log(f"settings window error: {exc}")
        finally:
            self._settings_open = False

    def run(self):
        for target in (self.serve, self.register_loop, self.dial_loop, self.ping_loop, self.watch_clipboard):
            threading.Thread(target=target, daemon=True).start()
        self.icon = pystray.Icon("clickboard", icon_image(COLOUR_IDLE), "Clickboard",
                                 menu=pystray.Menu(lambda: self.build_menu()))
        if not self.cfg.api_key:
            threading.Timer(1.0, self.open_settings).start()
        self.icon.run()


def icon_image(colour):
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((14, 10, 50, 58), radius=6, fill=colour)
    d.rounded_rectangle((24, 4, 40, 16), radius=3, fill=(60, 60, 60, 255))
    d.line((22, 30, 42, 30), fill=(255, 255, 255, 220), width=3)
    d.line((22, 40, 36, 40), fill=(255, 255, 255, 220), width=3)
    return img


# -- Settings window ---------------------------------------------------------

class SettingsWindow:
    def __init__(self, app: App):
        self.app = app

    def run(self):
        import tkinter as tk
        from tkinter import ttk, messagebox
        self.tk, self.ttk, self.messagebox = tk, ttk, messagebox
        app = self.app
        root = tk.Tk()
        self.root = root
        root.title("Clickboard settings")

        def edit_menu(event):
            w = event.widget
            m = tk.Menu(w, tearoff=0)
            m.add_command(label="Cut", command=lambda: w.event_generate("<<Cut>>"))
            m.add_command(label="Copy", command=lambda: w.event_generate("<<Copy>>"))
            m.add_command(label="Paste", command=lambda: w.event_generate("<<Paste>>"))
            m.add_separator()
            m.add_command(label="Select all", command=lambda: w.select_range(0, "end"))
            w.focus_set()
            m.tk_popup(event.x_root, event.y_root)
        root.bind_class("TEntry", "<Button-3>", edit_menu)

        outer = ttk.Frame(root, padding=16)
        outer.pack(fill="both", expand=True)

        ttk.Label(outer, text="Tiny-Web API key").grid(row=0, column=0, sticky="w")
        self.key_var = tk.StringVar(value=app.cfg.api_key)
        key_entry = ttk.Entry(outer, textvariable=self.key_var, width=48, show="\u2022")
        key_entry.grid(row=1, column=0, sticky="we", pady=(2, 0))
        ttk.Button(outer, text="Get a free key", command=lambda: webbrowser.open(SIGNUP_URL)).grid(row=1, column=1, padx=(8, 0))

        ttk.Label(outer, text="This machine's name").grid(row=2, column=0, sticky="w", pady=(12, 0))
        self.name_var = tk.StringVar(value=app.cfg.name)
        ttk.Entry(outer, textvariable=self.name_var, width=48).grid(row=3, column=0, sticky="we", pady=(2, 0))
        ttk.Button(outer, text="Save", command=self.save).grid(row=3, column=1, padx=(8, 0))

        self.status_var = tk.StringVar()
        ttk.Label(outer, textvariable=self.status_var, wraplength=460, foreground="#555").grid(
            row=4, column=0, columnspan=2, sticky="w", pady=(12, 0))

        ttk.Label(outer, text="Your machines", font=("TkDefaultFont", 10, "bold")).grid(row=5, column=0, sticky="w", pady=(16, 4))
        self.list_frame = ttk.Frame(outer)
        self.list_frame.grid(row=6, column=0, columnspan=2, sticky="we")
        self._shown = None

        outer.columnconfigure(0, weight=1)
        self.tick()

        root.update_idletasks()
        root.minsize(root.winfo_width(), root.winfo_height())
        root.lift()
        root.attributes("-topmost", True)
        root.after(300, lambda: root.attributes("-topmost", False))
        root.after(100, root.focus_force)
        if not app.cfg.api_key:
            root.after(150, key_entry.focus_set)
        root.mainloop()

    def save(self):
        key = self.key_var.get().strip()
        name = "".join(c for c in self.name_var.get().strip() if c.isalnum() or c in " .-_")[:64]
        if not key:
            self.messagebox.showerror("Clickboard", "Paste your Tiny-Web API key first.\nNo key yet? Click 'Get a free key'.")
            return
        if not name:
            self.messagebox.showerror("Clickboard", "Give this machine a name.")
            return
        self.app.cfg.api_key, self.app.cfg.name = key, name
        self.app.cfg.save()
        self.app.set_status("Checking in with Tiny-Web...")
        self.app.wake.set()

    def remove(self, device_id, name):
        if not self.messagebox.askyesno("Clickboard", f"Remove {name} from your Clickboard?\n\nIt will stop syncing immediately."):
            return

        def work():
            r = api_post("clickboard-remove.php", self.app.cfg.api_key, {"device_id": device_id})
            if not r.get("ok"):
                self.app.set_status(r.get("error", "Couldn't remove that machine"), warn=True)
            self.app.wake.set()
        threading.Thread(target=work, daemon=True).start()

    def tick(self):
        app = self.app
        plan = app.plan or {}
        line = app.status_line()
        if plan:
            line += f"\n{plan.get('name', 'Free')} plan \u00b7 {len(app.peers) + 1} of {plan.get('max_devices', '?')} machines in use"
        self.status_var.set(line)

        rows = [("this", app.cfg.name + " (this machine)", True)]
        for p in sorted(app.peers.values(), key=lambda d: d["name"].lower()):
            link = app.links.get(p["device_id"])
            rows.append((p["device_id"], p["name"], bool(link and link.alive)))
        if rows != self._shown:
            self._shown = rows
            for child in self.list_frame.winfo_children():
                child.destroy()
            for i, (pid, name, up) in enumerate(rows):
                self.ttk.Label(self.list_frame, text=("\u25cf " if up else "\u25cb ") + name).grid(row=i, column=0, sticky="w", pady=2)
                if pid != "this":
                    self.ttk.Label(self.list_frame, text="connected" if up else "not connected",
                                   foreground="#0d9488" if up else "#999").grid(row=i, column=1, sticky="w", padx=12)
                    self.ttk.Button(self.list_frame, text="Remove",
                                    command=lambda d=pid, n=name: self.remove(d, n)).grid(row=i, column=2, sticky="e")
            self.list_frame.columnconfigure(1, weight=1)
        self.root.after(1000, self.tick)


def main():
    App().run()


if __name__ == "__main__":
    main()
