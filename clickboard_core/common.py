"""Shared settings for apps built on clickboard_core: paths, ports, timings and logging.

Call set_app() once at start-up so each app gets its own config folder, log and received-files folder.

Part of clickboard_core. PolyForm Small Business License 1.0.0, see LICENSE.
"""
import os
import platform
import sys
import time
from pathlib import Path

CORE_VERSION = "1.0.1"

API_BASE = "https://tiny-web.uk/api/"
DEFAULT_PORT = 47800      # TCP: machine-to-machine TLS
BEACON_PORT = 47802       # UDP: passphrase-mode machines announce themselves on the LAN
BEACON_EVERY = 5          # seconds between passphrase-mode announcements
LOCAL_SEEN_FOR = 30       # a passphrase-mode machine not heard from in this long is offline
MIN_PASSPHRASE = 8
REGISTER_EVERY = 60       # seconds between check-ins with Tiny-Web
DIAL_EVERY = 5            # seconds between attempts to reach unconnected machines
PING_EVERY = 20           # keepalive; a link silent for 3x this is dropped
POLL_EVERY = 0.4          # seconds between local clipboard checks
MAX_CLIP_BYTES = 32 * 1024 * 1024       # largest single frame (text or image)
CHUNK_BYTES = 1024 * 1024               # file transfer chunk size
FILES_MAX_TOTAL = 2 * 1024 ** 3         # don't send more than this per copy
IMAGE_TYPES = ("image/png", "image/jpeg", "image/jpg", "image/gif", "image/webp",
               "image/bmp", "image/x-bmp", "image/tiff")

# Set by set_app(); defaults suit Clickboard.
APP_NAME = "Clickboard"
USER_AGENT = "Clickboard"
CONFIG_DIR = CONFIG_FILE = CERT_FILE = KEY_FILE = LOG_FILE = RECEIVED_DIR = None


def set_app(name: str, version: str = "0"):
    """Name the app using the core: decides config/log/received folders and the API user agent."""
    global APP_NAME, USER_AGENT, CONFIG_DIR, CONFIG_FILE, CERT_FILE, KEY_FILE, LOG_FILE, RECEIVED_DIR
    APP_NAME = name
    USER_AGENT = f"{name}/{version} clickboard_core/{CORE_VERSION}"
    if platform.system() == "Windows":
        CONFIG_DIR = Path(os.environ.get("APPDATA", str(Path.home()))) / name
    else:
        CONFIG_DIR = Path.home() / ".config" / name.lower()
    CONFIG_FILE = CONFIG_DIR / "config.json"
    CERT_FILE = CONFIG_DIR / "cert.pem"
    KEY_FILE = CONFIG_DIR / "key.pem"
    LOG_FILE = CONFIG_DIR / f"{name.lower()}.log"
    RECEIVED_DIR = Path.home() / name / "Received"


set_app("Clickboard")


def log(msg):
    line = f"[{APP_NAME.lower()} {time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    if sys.stderr:                       # None when running windowless (pythonw on Windows)
        try:
            print(line, file=sys.stderr, flush=True)
        except Exception:
            pass
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        if LOG_FILE.exists() and LOG_FILE.stat().st_size > 1_000_000:
            LOG_FILE.replace(LOG_FILE.with_suffix(".log.old"))
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except Exception:
        pass
