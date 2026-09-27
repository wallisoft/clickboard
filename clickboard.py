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
import hmac
import io
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
from urllib.parse import quote, unquote, urlparse

import pyperclip
import pystray
from PIL import Image, ImageDraw
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

VERSION = "2.4.0"
API_BASE = "https://tiny-web.uk/api/"
SIGNUP_URL = "https://clickboard.eur.bz/#signup"
SIGNUP_EMAIL = "signup@tiny-web.uk"        # fallbacks if signup-info.php is unreachable
SIGNUP_SMS_FALLBACK = "+447576556717"
DEFAULT_PORT = 47800
CONTROL_PORT = 47801      # localhost only: lets the launcher talk to a running copy
BEACON_PORT = 47802       # UDP: local-mode machines announce themselves on the LAN
BEACON_EVERY = 5          # seconds between local-mode announcements
LOCAL_SEEN_FOR = 30       # a local machine not heard from in this long is offline
MIN_PASSPHRASE = 8
IMAGE_TYPES = ("image/png", "image/jpeg", "image/jpg", "image/gif", "image/webp",
               "image/bmp", "image/x-bmp", "image/tiff")
REGISTER_EVERY = 60       # seconds between check-ins with Tiny-Web
DIAL_EVERY = 5            # seconds between attempts to reach unconnected machines
POLL_EVERY = 0.4          # seconds between local clipboard checks
PING_EVERY = 20           # keepalive; a link silent for 3x this is dropped
MAX_CLIP_BYTES = 32 * 1024 * 1024       # largest single frame (text or image)
CHUNK_BYTES = 1024 * 1024               # file transfer chunk size
FILES_MAX_TOTAL = 2 * 1024 ** 3         # don't send more than this per copy
RECEIVED_DIR = Path.home() / "Clickboard" / "Received"

if platform.system() == "Windows":
    CONFIG_DIR = Path(os.environ.get("APPDATA", str(Path.home()))) / "Clickboard"
else:
    CONFIG_DIR = Path.home() / ".config" / "clickboard"
CONFIG_FILE = CONFIG_DIR / "config.json"
CERT_FILE = CONFIG_DIR / "cert.pem"
KEY_FILE = CONFIG_DIR / "key.pem"

COLOUR_OK = (34, 197, 94, 255)        # green: syncing with at least one machine
COLOUR_OFF = (249, 115, 22, 255)      # orange: not connected (or needs attention)
COLOUR_PAUSED = (249, 115, 22, 255)   # orange too: paused by you (menu says which)


def log(msg):
    print(f"[clickboard {time.strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


# -- Config ------------------------------------------------------------------

class Config:
    FIELDS = ("mode", "api_key", "passphrase", "device_id", "name", "port", "paused")

    def __init__(self):
        self.mode = "account"     # "account" (Tiny-Web key) or "local" (shared passphrase)
        self.api_key = ""
        self.passphrase = ""
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


# -- Clipboard backends --------------------------------------------------------

class Clip:
    """What's on the clipboard: kind is 'text', 'image' (PNG bytes) or 'files' (paths)."""

    def __init__(self, kind, text=None, png=None, paths=None):
        self.kind, self.text, self.png, self.paths = kind, text, png, paths or []

    @property
    def sig(self):
        if self.kind == "text":
            return ("text", hashlib.sha1(self.text.encode("utf-8", "replace")).hexdigest())
        if self.kind == "image":
            return ("image", hashlib.sha1(self.png).hexdigest())
        return ("files", tuple(self.paths))


class LinuxBackend:
    """xclip where there's an X display (including XWayland), wl-clipboard otherwise."""

    def __init__(self):
        self.use_x = bool(os.environ.get("DISPLAY")) and shutil.which("xclip")
        self.use_wl = not self.use_x and bool(os.environ.get("WAYLAND_DISPLAY")) and shutil.which("wl-paste")
        desk = os.environ.get("XDG_CURRENT_DESKTOP", "").upper()
        self.gnome_files = any(d in desk for d in ("GNOME", "UNITY", "BUDGIE", "PANTHEON", "CINNAMON"))
        self._last_token = None
        self._last_image_read = 0.0
        if not (self.use_x or self.use_wl):
            log("no clipboard tool found (install xclip or wl-clipboard)")

    def _get(self, target=None, timeout=3):
        if self.use_x:
            cmd = ["xclip", "-selection", "clipboard", "-o"] + (["-t", target] if target else [])
        elif self.use_wl:
            cmd = ["wl-paste", "--no-newline"] + (["--type", target] if target else [])
        else:
            return None
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=timeout)
            return r.stdout if r.returncode == 0 else None
        except Exception:
            return None

    def _put(self, data: bytes, target=None):
        if self.use_x:
            cmd = ["xclip", "-selection", "clipboard", "-i"] + (["-t", target] if target else [])
        elif self.use_wl:
            cmd = ["wl-copy"] + (["--type", target] if target else [])
        else:
            return
        # xclip/wl-copy stay running to serve the clipboard, so never capture their output.
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p.stdin.write(data)
        p.stdin.close()

    def targets(self):
        if self.use_x:
            raw = self._get("TARGETS")
        elif self.use_wl:
            try:
                r = subprocess.run(["wl-paste", "--list-types"], capture_output=True, timeout=3)
                raw = r.stdout if r.returncode == 0 else None
            except Exception:
                raw = None
        else:
            raw = None
        return set(raw.decode(errors="ignore").split()) if raw else set()

    def read_if_changed(self):
        """Return a Clip if the clipboard may have changed since last time, else None."""
        t = self.targets()
        if not t:
            return None
        token = None
        if self.use_x and "TIMESTAMP" in t:
            ts = self._get("TIMESTAMP")
            if ts:                      # some owners advertise TIMESTAMP but don't supply it
                token = ("ts", ts)
        if token is None:
            token = ("targets", tuple(sorted(t)))
        if token[0] == "ts" and token == self._last_token:
            return None
        changed_token = token != self._last_token
        self._last_token = token

        if "x-special/gnome-copied-files" in t or "text/uri-list" in t:
            raw = self._get("x-special/gnome-copied-files") if "x-special/gnome-copied-files" in t else None
            lines = raw.decode(errors="ignore").splitlines()[1:] if raw else []
            if not lines and "text/uri-list" in t:
                raw = self._get("text/uri-list")
                lines = raw.decode(errors="ignore").splitlines() if raw else []
            paths = []
            for line in lines:
                line = line.strip()
                if line.startswith("file://"):
                    path = unquote(urlparse(line).path)
                    if os.path.exists(path):
                        paths.append(path)
            if paths:
                return Clip("files", paths=paths)
        img_type = next((x for x in IMAGE_TYPES if x in t), None)
        if img_type:
            # No usable change timestamp: re-read the image at most every 2 seconds.
            if token[0] == "targets" and not changed_token and time.time() - self._last_image_read < 2:
                return None
            self._last_image_read = time.time()
            data = self._get(img_type, timeout=10)
            png = to_png(data, img_type) if data else None
            if png:
                return Clip("image", png=png)
        for target in ("UTF8_STRING", "text/plain;charset=utf-8", "text/plain", None):
            if target is None or target in t:
                raw = self._get(target)
                if raw is not None:
                    return Clip("text", text=raw.decode("utf-8", errors="replace"))
        return None

    def write_text(self, text: str):
        self._put(text.encode("utf-8"))

    def write_image(self, png: bytes):
        self._put(png, "image/png")

    def write_files(self, paths):
        uris = [f"file://{quote(str(p))}" for p in paths]
        if self.gnome_files:
            self._put(("copy\n" + "\n".join(uris)).encode(), "x-special/gnome-copied-files")
        else:
            self._put(("\r\n".join(uris) + "\r\n").encode(), "text/uri-list")


class TextOnlyBackend:
    """Fallback anywhere else (until the Windows backend lands): plain text via pyperclip."""

    def __init__(self):
        self._last = None

    def read_if_changed(self):
        try:
            text = pyperclip.paste()
        except Exception:
            return None
        if text == self._last:
            return None
        self._last = text
        return Clip("text", text=text)

    def write_text(self, text):
        self._last = text
        pyperclip.copy(text)

    def write_image(self, png):
        pass

    def write_files(self, paths):
        pass


def to_png(data: bytes, mime: str):
    """Other image formats are converted, so the receiving side always gets PNG."""
    if mime == "image/png":
        return data
    try:
        img = Image.open(io.BytesIO(data))
        if img.mode not in ("RGB", "RGBA"):
            img = img.convert("RGBA")
        out = io.BytesIO()
        img.save(out, "PNG")
        return out.getvalue()
    except Exception as exc:
        log(f"couldn't convert {mime} image: {exc}")
        return None


def local_key(passphrase: str) -> bytes:
    """Slow on purpose, so a captured announcement can't be cheaply brute-forced."""
    return hashlib.scrypt(passphrase.encode("utf-8"), salt=b"clickboard-local-v1",
                          n=2 ** 14, r=8, p=1, dklen=32)


def make_backend():
    return LinuxBackend() if platform.system() == "Linux" else TextOnlyBackend()


def human_size(n: int) -> str:
    for unit in ("bytes", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "bytes" else f"{n:.1f} {unit}"
        n /= 1024


def safe_rel(path: str):
    """A received relative path, or None if it tries to escape the destination."""
    parts = [p for p in Path(path.replace("\\", "/")).parts if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts) or Path(path).is_absolute():
        return None
    return Path(*parts)


def signup_info() -> dict:
    """Signup email + SMS number from Tiny-Web (load-balanced there), with fallbacks."""
    info = {"email": SIGNUP_EMAIL, "sms_number": SIGNUP_SMS_FALLBACK}
    try:
        req = urllib.request.Request(API_BASE + "signup-info.php",
                                     headers={"User-Agent": f"Clickboard/{VERSION}"})
        with urllib.request.urlopen(req, timeout=6) as r:
            data = json.loads(r.read())
        if data.get("ok"):
            info["email"] = data.get("email") or info["email"]
            info["sms_number"] = data.get("sms_number") or info["sms_number"]
    except Exception as exc:
        log(f"signup info unavailable, using built-in details: {exc}")
    return info


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
        self.rx = {}   # incoming file transfers by id
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
                kind = header.get("type")
                if kind == "clip":
                    self.app.on_remote_clip(self.peer_id, header, payload)
                elif kind in ("files_begin", "dir", "file_chunk", "files_end"):
                    self.app.on_remote_files(self, header, payload)
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
        self.backend = make_backend()
        self.last_sig = None
        self.clip_lock = threading.Lock()
        self.wake = threading.Event()
        self._last_wake = 0.0
        self.icon = None
        self._settings_open = False
        self._local_key = None
        self._local_group = None
        self._set_local_key()
        self._build_contexts()

    def _set_local_key(self):
        if self.cfg.mode == "local" and len(self.cfg.passphrase) >= MIN_PASSPHRASE:
            self._local_key = local_key(self.cfg.passphrase)
            self._local_group = hashlib.sha256(self._local_key + b"group").hexdigest()[:16]
        else:
            self._local_key = self._local_group = None

    def reset_for_mode_change(self):
        """Called after Settings switches between account and local mode, or changes key/passphrase."""
        self._set_local_key()
        for link in list(self.links.values()):
            link.close("settings changed")
        self.peers, self.peers_loaded, self.plan = {}, False, None
        self._build_contexts()
        self.set_status("")
        self.wake.set()

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

    def apply_peers(self, fresh: dict, announce: bool = True):
        joined = [d for pid, d in fresh.items() if pid not in self.peers] if (self.peers_loaded and announce) else []
        gone = [pid for pid in self.peers if pid not in fresh]
        certs_changed = {p.get("cert_fp") for p in fresh.values()} != {p.get("cert_fp") for p in self.peers.values()}
        self.peers = fresh
        self.peers_loaded = True
        if certs_changed:
            self._build_contexts()
        for pid in gone:
            link = self.links.get(pid)
            if link:
                link.close("no longer in your group")
        for d in joined:
            if self.cfg.mode == "local":
                self.notify(f"{d['name']} joined your Clickboard (local passphrase).")
            else:
                self.notify(f"{d['name']} joined your Clickboard. Not yours? Remove it in Settings.")
        if joined or gone:
            self.refresh_ui()

    def register_now(self):
        if self.cfg.mode == "local":
            if not self._local_key:
                self.set_status(f"Set a passphrase of at least {MIN_PASSPHRASE} characters in Settings", warn=True)
            else:
                self.plan = {"name": "Local", "max_devices": None, "features": {"images": True, "files": True}}
                self.set_status("")
            return
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
        if self.cfg.mode != "account":
            return
        self.plan = r.get("plan")
        self.apply_peers({d["device_id"]: d for d in r.get("devices", [])})
        self.set_status("")

    # ---- local mode: LAN announcements signed with the shared passphrase ----
    def _beacon_mac(self, device_id, port, fp):
        return hmac.new(self._local_key, f"{device_id}|{port}|{fp}".encode(), hashlib.sha256).hexdigest()

    def beacon_send_loop(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        fp = der_fingerprint(ssl.PEM_cert_to_DER_cert(self.cert_pem))
        while self.running:
            if self.cfg.mode == "local" and self._local_key:
                msg = json.dumps({
                    "v": 1, "group": self._local_group, "device_id": self.cfg.device_id,
                    "name": self.cfg.name, "port": self.cfg.port, "cert_pem": self.cert_pem,
                    "mac": self._beacon_mac(self.cfg.device_id, self.cfg.port, fp),
                }).encode()
                try:
                    s.sendto(msg, ("255.255.255.255", BEACON_PORT))
                except OSError:
                    pass
                self._expire_local_peers()
            time.sleep(BEACON_EVERY)

    def _expire_local_peers(self):
        now = time.time()
        fresh = {}
        for pid, p in self.peers.items():
            p = dict(p)
            p["online"] = now - p.get("_seen", 0) < LOCAL_SEEN_FOR
            fresh[pid] = p
        self.peers = fresh

    def beacon_listen_loop(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("", BEACON_PORT))
        except OSError as exc:
            log(f"local discovery unavailable: {exc}")
            return
        while self.running:
            try:
                data, (addr, _) = s.recvfrom(8192)
                if self.cfg.mode != "local" or not self._local_key:
                    continue
                b = json.loads(data)
                if b.get("group") != self._local_group or b.get("device_id") == self.cfg.device_id:
                    continue
                pem, port, pid = b["cert_pem"], int(b["port"]), str(b["device_id"])
                fp = der_fingerprint(ssl.PEM_cert_to_DER_cert(pem))
                if not hmac.compare_digest(self._beacon_mac(pid, port, fp), str(b.get("mac", ""))):
                    continue      # same group id but wrong passphrase proof: ignore
            except Exception:
                continue
            fresh = dict(self.peers)
            fresh[pid] = {"device_id": pid, "name": str(b.get("name", "machine"))[:64], "platform": "",
                          "lan_addrs": [addr], "port": port, "cert_pem": pem, "cert_fp": fp,
                          "online": True, "_seen": time.time()}
            self.apply_peers(fresh)

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
    def features(self):
        return (self.plan or {}).get("features", {}) or {}

    def watch_clipboard(self):
        first = self.backend.read_if_changed()      # don't send whatever was there at startup
        if first:
            self.last_sig = first.sig
        while self.running:
            try:
                clip = self.backend.read_if_changed()
            except Exception as exc:
                log(f"clipboard read failed: {exc}")
                clip = None
            if clip:
                with self.clip_lock:
                    changed = clip.sig != self.last_sig
                    if changed:
                        self.last_sig = clip.sig
                if changed and not self.cfg.paused and self.links:
                    self.broadcast(clip)
            time.sleep(POLL_EVERY)

    def broadcast(self, clip: Clip):
        links = [link for link in self.links.values() if link.alive]
        if clip.kind == "text":
            if not clip.text:
                return
            data = clip.text.encode("utf-8")
            if len(data) > MAX_CLIP_BYTES:
                log("text too large to send")
                return
            for link in links:
                link.send({"type": "clip", "mime": "text/plain;charset=utf-8"}, data)
        elif clip.kind == "image":
            if self.features().get("images") is False:
                return
            if len(clip.png) > MAX_CLIP_BYTES:
                self.notify("That image is too large to send.")
                return
            for link in links:
                link.send({"type": "clip", "mime": "image/png"}, clip.png)
        elif clip.kind == "files":
            if self.features().get("files") is False:
                self.notify("Sending files needs a paid plan.")
                return
            total = 0
            for p in clip.paths:
                if os.path.isdir(p):
                    for root, _, files in os.walk(p):
                        for f in files:
                            try:
                                total += os.path.getsize(os.path.join(root, f))
                            except OSError:
                                pass
                else:
                    try:
                        total += os.path.getsize(p)
                    except OSError:
                        pass
            if total > FILES_MAX_TOTAL:
                self.notify(f"Not sending {human_size(total)}: that's over the {human_size(FILES_MAX_TOTAL)} limit.")
                return
            for link in links:
                threading.Thread(target=self._send_files, args=(link, clip.paths, total), daemon=True).start()

    def _send_files(self, link, paths, total):
        fid = str(uuid.uuid4())
        link.send({"type": "files_begin", "id": fid, "items": [os.path.basename(p.rstrip("/")) for p in paths],
                   "total": total})

        def send_file(full, rel):
            offset = 0
            try:
                with open(full, "rb") as fh:
                    while link.alive:
                        chunk = fh.read(CHUNK_BYTES)
                        eof = len(chunk) < CHUNK_BYTES
                        link.send({"type": "file_chunk", "id": fid, "path": rel, "offset": offset, "eof": eof}, chunk)
                        offset += len(chunk)
                        if eof:
                            break
            except OSError as exc:
                log(f"skipped {full}: {exc}")

        for p in paths:
            p = p.rstrip("/")
            base = os.path.dirname(p)
            if os.path.isdir(p):
                for root, dirs, files in os.walk(p):
                    rel_root = os.path.relpath(root, base)
                    link.send({"type": "dir", "id": fid, "path": rel_root})
                    for f in files:
                        send_file(os.path.join(root, f), os.path.join(rel_root, f))
            elif os.path.isfile(p):
                send_file(p, os.path.basename(p))
        link.send({"type": "files_end", "id": fid})
        name = self.peers.get(link.peer_id, {}).get("name", "another machine")
        log(f"sent {len(paths)} item(s), {human_size(total)}, to {name}")

    def on_remote_clip(self, peer_id, header, payload):
        if self.cfg.paused:
            return
        mime = str(header.get("mime", ""))
        try:
            if mime.startswith("text/plain"):
                clip = Clip("text", text=payload.decode("utf-8", errors="replace"))
                with self.clip_lock:
                    self.last_sig = clip.sig    # so the watcher doesn't bounce it straight back
                    self.backend.write_text(clip.text)
            elif mime == "image/png":
                clip = Clip("image", png=payload)
                with self.clip_lock:
                    self.last_sig = clip.sig
                    self.backend.write_image(payload)
        except Exception as exc:
            log(f"can't write the clipboard: {exc}")

    def on_remote_files(self, link, header, payload):
        kind, fid = header.get("type"), str(header.get("id", ""))
        if kind == "files_begin":
            if self.cfg.paused:
                return
            dest = RECEIVED_DIR / time.strftime("%Y-%m-%d %H%M%S")
            n = 1
            while dest.exists():
                n += 1
                dest = RECEIVED_DIR / (time.strftime("%Y-%m-%d %H%M%S") + f" ({n})")
            dest.mkdir(parents=True, exist_ok=True)
            items = [i for i in (header.get("items") or []) if safe_rel(str(i))]
            link.rx[fid] = {"dest": dest, "items": items, "total": int(header.get("total", 0)), "open": {}}
            return
        rx = link.rx.get(fid)
        if not rx:
            return
        if kind == "dir":
            rel = safe_rel(str(header.get("path", "")))
            if rel:
                (rx["dest"] / rel).mkdir(parents=True, exist_ok=True)
        elif kind == "file_chunk":
            rel = safe_rel(str(header.get("path", "")))
            if not rel:
                return
            target = rx["dest"] / rel
            fh = rx["open"].get(rel)
            if fh is None:
                target.parent.mkdir(parents=True, exist_ok=True)
                fh = open(target, "wb")
                rx["open"][rel] = fh
            fh.write(payload)
            if header.get("eof"):
                fh.close()
                del rx["open"][rel]
        elif kind == "files_end":
            for fh in rx["open"].values():
                fh.close()
            del link.rx[fid]
            paths = [str(rx["dest"] / i) for i in rx["items"] if (rx["dest"] / i).exists()]
            if not paths:
                return
            clip = Clip("files", paths=paths)
            with self.clip_lock:
                self.last_sig = clip.sig
                try:
                    self.backend.write_files(paths)
                except Exception as exc:
                    log(f"can't put received files on the clipboard: {exc}")
            name = self.peers.get(link.peer_id, {}).get("name", "another machine")
            self.notify(f"Received {len(paths)} item(s), {human_size(rx['total'])}, from {name}. "
                        f"Paste in your file manager, or find them in {rx['dest']}")

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
        if self.cfg.paused:
            colour = COLOUR_PAUSED
        elif self.connected_count() and not self.warn:
            colour = COLOUR_OK
        else:
            colour = COLOUR_OFF
        try:
            self.icon.icon = icon_image(colour)
            self.icon.title = f"Clickboard - {self.status_line()}"
            self.icon.update_menu()
        except Exception:
            pass

    def build_menu(self):
        items = [
            pystray.MenuItem(lambda item: "Resume sync" if self.cfg.paused else "Pause sync",
                             self.toggle_pause, default=True),
            pystray.MenuItem(self.status_line(), None, enabled=False),
            pystray.Menu.SEPARATOR,
        ]
        for p in sorted(self.peers.values(), key=lambda d: d["name"].lower()):
            link = self.links.get(p["device_id"])
            mark = "\u25cf " if (link and link.alive) else "\u25cb "
            items.append(pystray.MenuItem(mark + p["name"], None, enabled=False))
        if self.peers:
            items.append(pystray.Menu.SEPARATOR)
        items += [
            pystray.MenuItem("Settings...", lambda: self.open_settings()),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", self.quit),
        ]
        return items

    def toggle_pause(self):
        self.set_paused(not self.cfg.paused)

    def set_paused(self, paused: bool):
        self.cfg.paused = paused
        self.cfg.save()
        log("sync paused" if paused else "sync resumed")
        self.refresh_ui()

    # ---- control channel: "clickboard --toggle" etc. from the dock/launcher ----
    def control_loop(self):
        try:
            cs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            cs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            cs.bind(("127.0.0.1", CONTROL_PORT))
            cs.listen(4)
        except OSError as exc:
            log(f"control channel unavailable: {exc}")
            return
        while self.running:
            try:
                conn, _ = cs.accept()
            except OSError:
                continue
            with conn:
                try:
                    conn.settimeout(2)
                    cmd = conn.recv(64).decode(errors="ignore").strip()
                    conn.sendall(b"ok\n")
                except OSError:
                    continue
            if cmd == "toggle":
                self.toggle_pause()
            elif cmd == "pause":
                self.set_paused(True)
            elif cmd == "resume":
                self.set_paused(False)
            elif cmd == "settings":
                self.open_settings()
            elif cmd == "quit":
                self.quit()

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
        for target in (self.serve, self.register_loop, self.dial_loop, self.ping_loop,
                       self.watch_clipboard, self.control_loop,
                       self.beacon_send_loop, self.beacon_listen_loop):
            threading.Thread(target=target, daemon=True).start()
        self.icon = pystray.Icon("clickboard", icon_image(COLOUR_PAUSED if self.cfg.paused else COLOUR_OFF), "Clickboard",
                                 menu=pystray.Menu(lambda: self.build_menu()))
        if not (self.cfg.api_key or (self.cfg.mode == "local" and self._local_key)):
            threading.Timer(1.0, self.open_settings).start()
        self.icon.run()


def icon_image(colour):
    """A plain coloured dot: green syncing, orange not connected, grey paused."""
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.ellipse((8, 8, 56, 56), fill=colour, outline=(255, 255, 255, 200), width=3)
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

        self.mode_var = tk.StringVar(value=app.cfg.mode)
        modes = ttk.Frame(outer)
        modes.grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Radiobutton(modes, text="Tiny-Web key (works on any network)", value="account",
                        variable=self.mode_var, command=self.show_mode).pack(anchor="w")
        ttk.Radiobutton(modes, text="Shared passphrase (no signup, same network)", value="local",
                        variable=self.mode_var, command=self.show_mode).pack(anchor="w")

        self.key_label = ttk.Label(outer)
        self.key_label.grid(row=0, column=0, sticky="w")
        self.key_var = tk.StringVar(value=app.cfg.api_key)
        self.pass_var = tk.StringVar(value=app.cfg.passphrase)
        self.key_entry = ttk.Entry(outer, textvariable=self.key_var, width=48, show="\u2022")
        self.pass_entry = ttk.Entry(outer, textvariable=self.pass_var, width=48)
        self.key_btn = ttk.Button(outer, text="Get a free key", command=self.show_signup)
        self.pass_btn = ttk.Button(outer, text="Generate", command=self.generate_passphrase)
        key_entry = self.key_entry

        # rows 1-2: mode radios are row 0; label/field/button are placed by show_mode()
        modes.grid_configure(row=0)
        self.key_label.grid_configure(row=1, pady=(10, 0))
        self.show_mode()

        ttk.Label(outer, text="This machine's name").grid(row=3, column=0, sticky="w", pady=(12, 0))
        self.name_var = tk.StringVar(value=app.cfg.name)
        ttk.Entry(outer, textvariable=self.name_var, width=48).grid(row=4, column=0, sticky="we", pady=(2, 0))
        ttk.Button(outer, text="Save", command=self.save).grid(row=4, column=1, padx=(8, 0))

        self.status_var = tk.StringVar()
        ttk.Label(outer, textvariable=self.status_var, wraplength=460, foreground="#555").grid(
            row=5, column=0, columnspan=2, sticky="w", pady=(12, 0))
        self.local_btn = ttk.Button(outer, text="Continue without an account",
                                    command=lambda: (self.mode_var.set("local"), self.show_mode()))

        ttk.Label(outer, text="Your machines", font=("TkDefaultFont", 10, "bold")).grid(row=7, column=0, sticky="w", pady=(16, 4))
        self.list_frame = ttk.Frame(outer)
        self.list_frame.grid(row=8, column=0, columnspan=2, sticky="we")
        self._shown = None

        outer.columnconfigure(0, weight=1)
        self.tick()

        root.update_idletasks()
        root.minsize(root.winfo_width(), root.winfo_height())
        root.lift()
        root.attributes("-topmost", True)
        root.after(300, lambda: root.attributes("-topmost", False))
        root.after(100, root.focus_force)
        if not app.cfg.api_key and app.cfg.mode == "account":
            root.after(150, key_entry.focus_set)
        root.mainloop()

    def show_mode(self):
        local = self.mode_var.get() == "local"
        for w in (self.key_entry, self.key_btn, self.pass_entry, self.pass_btn):
            w.grid_remove()
        if local:
            self.key_label.config(text=f"Shared passphrase ({MIN_PASSPHRASE}+ characters). Use the same one on each machine.")
            self.pass_entry.grid(row=2, column=0, sticky="we", pady=(2, 0))
            self.pass_btn.grid(row=2, column=1, padx=(8, 0))
        else:
            self.key_label.config(text="Tiny-Web API key")
            self.key_entry.grid(row=2, column=0, sticky="we", pady=(2, 0))
            self.key_btn.grid(row=2, column=1, padx=(8, 0))

    def generate_passphrase(self):
        import secrets
        words = ("amber", "anchor", "apple", "badger", "banjo", "beacon", "bramble", "cactus", "castle", "cobalt",
                 "comet", "copper", "dingo", "ember", "falcon", "fern", "garnet", "harbour", "hazel", "island",
                 "jigsaw", "kettle", "lantern", "lemon", "maple", "marble", "meadow", "nutmeg", "orbit", "otter",
                 "pebble", "pepper", "piano", "quartz", "raven", "ribbon", "saffron", "tango", "thistle", "tulip",
                 "velvet", "walnut", "willow", "yonder", "zephyr", "biscuit", "puffin", "saucer")
        self.pass_var.set("-".join(secrets.choice(words) for _ in range(4)))

    def show_signup(self):
        tk, ttk = self.tk, self.ttk
        win = tk.Toplevel(self.root)
        win.title("Get your free Tiny-Web key")
        win.transient(self.root)
        frame = ttk.Frame(win, padding=18)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Three quick steps. One key works for all Tiny-Web services.",
                  wraplength=440).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 12))

        email_var = tk.StringVar(value=SIGNUP_EMAIL)
        sms_var = tk.StringVar(value="fetching...")

        def copy(text):
            self.root.clipboard_clear()
            self.root.clipboard_append(text)

        def step(row, num, title, detail, var=None, button=None):
            ttk.Label(frame, text=f"{num}.", font=("TkDefaultFont", 11, "bold")).grid(row=row, column=0, sticky="nw", padx=(0, 8))
            ttk.Label(frame, text=title, font=("TkDefaultFont", 10, "bold")).grid(row=row, column=1, sticky="w")
            ttk.Label(frame, text=detail, wraplength=400, foreground="#555").grid(row=row + 1, column=1, sticky="w")
            if var is not None:
                box = ttk.Frame(frame)
                box.grid(row=row + 2, column=1, sticky="w", pady=(4, 12))
                ttk.Entry(box, textvariable=var, width=26, state="readonly", font=("monospace", 11)).pack(side="left")
                ttk.Button(box, text="Copy", command=lambda: copy(var.get())).pack(side="left", padx=6)
                if button:
                    ttk.Button(box, text=button[0], command=button[1]).pack(side="left")
            else:
                ttk.Frame(frame, height=12).grid(row=row + 2, column=1)

        step(1, 1, "Email us your mobile number",
             "From the email address you want on your account, send your mobile number to:",
             email_var, ("Open email", lambda: webbrowser.open(f"mailto:{email_var.get()}?subject=Clickboard%20signup")))
        step(4, 2, "Text us your email address",
             "From that same mobile, text the email address you just used to:", sms_var)
        step(7, 3, "Your key arrives by email",
             "Paste it into Clickboard's settings and click Save. That's it.")
        ttk.Button(frame, text="I've got my key", command=win.destroy).grid(row=10, column=1, sticky="e", pady=(4, 0))

        def load():
            info = signup_info()
            try:
                self.root.after(0, lambda: (email_var.set(info["email"]), sms_var.set(info["sms_number"])))
            except Exception:
                pass
        threading.Thread(target=load, daemon=True).start()
        win.lift()
        win.focus_force()

    def save(self):
        mode = self.mode_var.get()
        key = self.key_var.get().strip()
        passphrase = self.pass_var.get().strip()
        name = "".join(c for c in self.name_var.get().strip() if c.isalnum() or c in " .-_")[:64]
        if mode == "account" and not key:
            self.messagebox.showerror("Clickboard", "Paste your Tiny-Web API key first.\nNo key yet? Click 'Get a free key',\nor choose 'Shared passphrase' to use Clickboard without an account.")
            return
        if mode == "local" and len(passphrase) < MIN_PASSPHRASE:
            self.messagebox.showerror("Clickboard", f"Your passphrase needs at least {MIN_PASSPHRASE} characters.\n\nAnyone on the same network with the same passphrase can see your clipboard, so make it hard to guess. 'Generate' makes a good one.")
            return
        if not name:
            self.messagebox.showerror("Clickboard", "Give this machine a name.")
            return
        cfg = self.app.cfg
        changed = (mode, key, passphrase) != (cfg.mode, cfg.api_key, cfg.passphrase)
        cfg.mode, cfg.api_key, cfg.passphrase, cfg.name = mode, key, passphrase, name
        cfg.save()
        self.app.set_status("Looking for your other machines..." if mode == "local" else "Checking in with Tiny-Web...")
        if changed:
            self.app.reset_for_mode_change()
        else:
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
        if plan and app.cfg.mode == "account":
            line += f"\n{plan.get('name', 'Free')} plan \u00b7 {len(app.peers) + 1} of {plan.get('max_devices', '?')} machines in use"
        elif app.cfg.mode == "local":
            line += "\nLocal mode: machines on this network with the same passphrase connect automatically."
        self.status_var.set(line)
        # Offer the no-account route when the key is the problem.
        low = (app.status or "").lower()
        if app.cfg.mode == "account" and app.warn and ("key" in low or "account" in low):
            self.local_btn.grid(row=6, column=0, sticky="w", pady=(6, 0))
        else:
            self.local_btn.grid_remove()

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
                if pid != "this" and app.cfg.mode == "account":
                    self.ttk.Label(self.list_frame, text="connected" if up else "not connected",
                                   foreground="#0d9488" if up else "#999").grid(row=i, column=1, sticky="w", padx=12)
                    self.ttk.Button(self.list_frame, text="Remove",
                                    command=lambda d=pid, n=name: self.remove(d, n)).grid(row=i, column=2, sticky="e")
                elif pid != "this":
                    self.ttk.Label(self.list_frame, text="connected" if up else "not connected",
                                   foreground="#0d9488" if up else "#999").grid(row=i, column=1, sticky="w", padx=12)
            self.list_frame.columnconfigure(1, weight=1)
        self.root.after(1000, self.tick)


def send_to_running(cmd: str) -> bool:
    """If Clickboard is already running, pass it a command and return True."""
    try:
        with socket.create_connection(("127.0.0.1", CONTROL_PORT), timeout=1) as s:
            s.sendall((cmd + "\n").encode())
            return s.recv(8).startswith(b"ok")
    except OSError:
        return False


def main():
    flags = {"--toggle": "toggle", "--pause": "pause", "--resume": "resume",
             "--settings": "settings", "--quit": "quit"}
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    # Launching again while running (e.g. clicking it in the dock) opens Settings.
    cmd = flags.get(arg, "settings")
    if send_to_running(cmd):
        return
    if cmd == "quit":
        return
    app = App()
    if cmd in ("pause", "resume"):
        app.cfg.paused = cmd == "pause"
        app.cfg.save()
    app.run()


if __name__ == "__main__":
    main()
