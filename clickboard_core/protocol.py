"""Wire protocol: [4-byte header length][JSON header][payload bytes], and Link, one live TLS connection.

Frames other than pings are handed to app.on_frame(link, header, payload).

Part of clickboard_core. PolyForm Small Business License 1.0.0, see LICENSE.
"""
import json
import platform
import socket
import struct
import threading

from . import common as C


def reuse_or_exclusive(sock):
    if platform.system() == "Windows":
        sock.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_EXCLUSIVEADDRUSE", -5), 1)
    else:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


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
    if size < 0 or size > C.MAX_CLIP_BYTES:
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
        self.rx = {}   # per-link state for features, e.g. incoming file transfers
        try:
            # Send small messages (e.g. mouse movements) immediately rather than batching them.
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
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
        self.sock.settimeout(C.PING_EVERY * 3)
        try:
            while self.alive:
                header, payload = recv_frame(self.sock)
                if header.get("type") != "ping":
                    self.app.on_frame(self, header, payload)
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
