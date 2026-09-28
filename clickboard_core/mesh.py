"""Mesh: discovery (Tiny-Web account or shared passphrase), mutual TLS and links between one user's machines.

Part of clickboard_core. PolyForm Small Business License 1.0.0, see LICENSE.
"""
import hashlib
import hmac
import json
import platform
import socket
import ssl
import threading
import time

from . import common as C
from .identity import der_fingerprint, ensure_identity, lan_addrs, local_key
from .protocol import Link, reuse_or_exclusive
from .tinyweb import api_post


class Mesh:
    """Finds this user's other machines and keeps TLS links to them.

    Two ways to find machines: a Tiny-Web account (key mode, works on any
    network) or a shared passphrase (local mode, same network). Either way,
    machines only trust certificates from their own group.

    Subclass it (or mix in features like ClipboardSync) and override:
      on_frame(link, header, payload)  frames for your features
      notify(msg)                      user-facing notices
      refresh_ui()                     status changed
    """

    def __init__(self, cfg, service: str):
        self.cfg = cfg
        self.service = service              # Tiny-Web service name, e.g. "clickboard"
        self.cert_file, self.key_file = C.CERT_FILE, C.KEY_FILE   # fixed per instance
        self.cert_pem = ensure_identity(self.cfg.device_id)
        self.running = True
        self.lock = threading.Lock()
        self.peers = {}            # device_id -> device dict
        self.peers_loaded = False
        self.links = {}            # device_id -> Link
        self.plan = None
        self.status = ""
        self.warn = False
        self.wake = threading.Event()
        self._last_wake = 0.0
        self._local_key = None
        self._local_group = None
        self._set_local_key()
        self._build_contexts()

    def start(self):
        """Start the networking threads."""
        for target in (self.serve, self.register_loop, self.dial_loop, self.ping_loop,
                       self.beacon_send_loop, self.beacon_listen_loop):
            threading.Thread(target=target, daemon=True).start()

    def stop(self):
        self.running = False
        for link in list(self.links.values()):
            link.close("shutting down")

    def remove_device(self, device_id: str) -> dict:
        r = api_post(f"{self.service}-remove.php", self.cfg.api_key, {"device_id": device_id})
        self.wake.set()
        return r

    # ---- hooks for the app (defaults do little) ----
    def on_frame(self, link, header, payload):
        pass

    def notify(self, msg):
        C.log(msg)

    def refresh_ui(self):
        pass

    def set_status(self, text, warn=False):
        if text != self.status or warn != self.warn:
            self.status, self.warn = text, warn
            if text:
                C.log(text)
            self.refresh_ui()

    def connected_count(self):
        return sum(1 for link in self.links.values() if link.alive)

    def _set_local_key(self):
        if self.cfg.mode == "local" and len(self.cfg.passphrase) >= C.MIN_PASSPHRASE:
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
            ctx.load_cert_chain(str(self.cert_file), str(self.key_file))
            ctx.verify_mode = ssl.CERT_REQUIRED
            if pems:
                ctx.load_verify_locations(cadata="\n".join(pems))
        self.srv_ctx, self.cli_ctx = srv, cli

    # ---- registration / discovery ----
    def register_loop(self):
        while self.running:
            self.register_now()
            self.wake.wait(C.REGISTER_EVERY)
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
                self.set_status(f"Set a passphrase of at least {C.MIN_PASSPHRASE} characters in Settings", warn=True)
            else:
                self.plan = {"name": "Local", "max_devices": None, "features": {"images": True, "files": True}}
                self.set_status("")
            return
        if not self.cfg.api_key:
            self.set_status("Add your Tiny-Web key in Settings", warn=True)
            return
        r = api_post(f"{self.service}-register.php", self.cfg.api_key, {
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
                    s.sendto(msg, ("255.255.255.255", C.BEACON_PORT))
                except OSError:
                    pass
                self._expire_local_peers()
            time.sleep(C.BEACON_EVERY)

    def _expire_local_peers(self):
        now = time.time()
        fresh = {}
        for pid, p in self.peers.items():
            p = dict(p)
            p["online"] = now - p.get("_seen", 0) < C.LOCAL_SEEN_FOR
            fresh[pid] = p
        self.peers = fresh

    def beacon_listen_loop(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            reuse_or_exclusive(s)
            s.bind(("", C.BEACON_PORT))
        except OSError as exc:
            C.log(f"local discovery unavailable: {exc}")
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
            reuse_or_exclusive(ls)
            ls.bind(("0.0.0.0", self.cfg.port))
            ls.listen(8)
        except OSError as exc:
            self.set_status(f"Can't listen on port {self.cfg.port} (is Clickboard already running?)", warn=True)
            C.log(f"listen failed: {exc}")
            return
        C.log(f"listening on port {self.cfg.port}")
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
            C.log(f"refused connection from {addr[0]}: {exc}")
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
            time.sleep(C.DIAL_EVERY)

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
        C.log(f"connected to {peer['name']}")
        self.refresh_ui()

    def on_link_closed(self, link, why):
        with self.lock:
            if self.links.get(link.peer_id) is link:
                del self.links[link.peer_id]
        name = self.peers.get(link.peer_id, {}).get("name", link.peer_id[:8])
        C.log(f"disconnected from {name}: {why}")
        self.refresh_ui()

    def ping_loop(self):
        while self.running:
            time.sleep(C.PING_EVERY)
            for link in list(self.links.values()):
                link.send({"type": "ping"})

    # ---- clipboard ----
