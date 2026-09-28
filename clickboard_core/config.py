"""Per-machine settings: mode, key or passphrase, device id, name.

Part of clickboard_core. PolyForm Small Business License 1.0.0, see LICENSE.
"""
import json
import os
import socket
import uuid

from . import common as C


class Config:
    FIELDS = ("mode", "api_key", "passphrase", "device_id", "name", "port", "paused")

    def __init__(self):
        self.mode = "account"     # "account" (Tiny-Web key) or "local" (shared passphrase)
        self.api_key = ""
        self.passphrase = ""
        self.device_id = str(uuid.uuid4())
        self.name = "".join(c for c in socket.gethostname().split(".")[0] if c.isalnum() or c in " .-_")[:64] or "machine"
        self.port = C.DEFAULT_PORT
        self.paused = False

    @classmethod
    def load(cls):
        cfg = cls()
        if C.CONFIG_FILE.exists():
            try:
                raw = json.loads(C.CONFIG_FILE.read_text())
                for k in cls.FIELDS:
                    if k in raw:
                        setattr(cfg, k, raw[k])
            except Exception as exc:
                C.log(f"config unreadable, starting fresh: {exc}")
        cfg.save()
        return cfg

    def save(self):
        C.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        C.CONFIG_FILE.write_text(json.dumps({k: getattr(self, k) for k in self.FIELDS}, indent=2))
        try:
            os.chmod(C.CONFIG_FILE, 0o600)
        except OSError:
            pass
