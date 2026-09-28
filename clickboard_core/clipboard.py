"""Clipboard: platform backends (text, images, files) and ClipboardSync, the mixin that syncs them over a Mesh.

Part of clickboard_core. PolyForm Small Business License 1.0.0, see LICENSE.
"""
import hashlib
import io
import os
import platform
import shutil
import struct
import subprocess
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import quote, unquote, urlparse

import pyperclip
from PIL import Image

from . import common as C


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
            C.log("no clipboard tool found (install xclip or wl-clipboard)")

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
        # Don't trust an unchanged TIMESTAMP to mean "nothing changed": some apps keep
        # ownership and just swap the contents. Text is cheap to re-read every poll;
        # only large images are throttled.
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
        img_type = next((x for x in C.IMAGE_TYPES if x in t), None)
        if img_type:
            # Same owner as last time: re-read the image at most every 2 seconds.
            if not changed_token and time.time() - self._last_image_read < 2:
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
        C.log(f"couldn't convert {mime} image: {exc}")
        return None


class WindowsBackend:
    """Windows clipboard via pywin32: text, images (PNG and bitmap) and Explorer files."""

    def __init__(self):
        import win32clipboard
        import win32con
        self.wc, self.con = win32clipboard, win32con
        self.CF_PNG = win32clipboard.RegisterClipboardFormat("PNG")
        self.CF_DROPEFFECT = win32clipboard.RegisterClipboardFormat("Preferred DropEffect")
        self._last_seq = None

    def _open(self):
        for _ in range(20):          # another app may briefly hold the clipboard
            try:
                self.wc.OpenClipboard()
                return True
            except Exception:
                time.sleep(0.05)
        return False

    def read_if_changed(self):
        seq = self.wc.GetClipboardSequenceNumber()     # Windows counts every change for us
        if seq == self._last_seq:
            return None
        if not self._open():
            return None                                # retry next poll
        self._last_seq = seq
        want_image = False
        try:
            if self.wc.IsClipboardFormatAvailable(self.con.CF_HDROP):
                paths = [p for p in self.wc.GetClipboardData(self.con.CF_HDROP) if os.path.exists(p)]
                if paths:
                    return Clip("files", paths=list(paths))
            if self.wc.IsClipboardFormatAvailable(self.CF_PNG):
                data = self.wc.GetClipboardData(self.CF_PNG)
                if data:
                    return Clip("image", png=bytes(data))
            if self.wc.IsClipboardFormatAvailable(self.con.CF_DIB):
                want_image = True
            elif self.wc.IsClipboardFormatAvailable(self.con.CF_UNICODETEXT):
                return Clip("text", text=self.wc.GetClipboardData(self.con.CF_UNICODETEXT))
        except Exception as exc:
            C.log(f"clipboard read failed: {exc}")
            return None
        finally:
            try:
                self.wc.CloseClipboard()
            except Exception:
                pass
        if want_image:
            try:
                from PIL import ImageGrab
                img = ImageGrab.grabclipboard()      # decodes Windows bitmaps for us
                if isinstance(img, Image.Image):
                    out = io.BytesIO()
                    img.save(out, "PNG")
                    return Clip("image", png=out.getvalue())
            except Exception as exc:
                C.log(f"couldn't read clipboard image: {exc}")
        return None

    def _write(self, fill):
        if not self._open():
            C.log("clipboard busy, couldn't write")
            return
        try:
            self.wc.EmptyClipboard()
            fill()
        finally:
            self.wc.CloseClipboard()
        self._last_seq = self.wc.GetClipboardSequenceNumber()

    def write_text(self, text):
        self._write(lambda: self.wc.SetClipboardText(text, self.con.CF_UNICODETEXT))

    def write_image(self, png):
        img = Image.open(io.BytesIO(png))
        bmp = io.BytesIO()
        img.convert("RGB").save(bmp, "BMP")
        dib = bmp.getvalue()[14:]                      # a DIB is a .bmp without its file header

        def fill():
            self.wc.SetClipboardData(self.con.CF_DIB, dib)
            self.wc.SetClipboardData(self.CF_PNG, png)  # lossless copy for apps that want PNG
        self._write(fill)

    def write_files(self, paths):
        # DROPFILES header: offset to file list (20), drop point (0,0), fNC=0, fWide=1 (UTF-16)
        header = struct.pack("<IiiII", 20, 0, 0, 0, 1)
        body = ("\0".join(str(p) for p in paths) + "\0\0").encode("utf-16-le")

        def fill():
            self.wc.SetClipboardData(self.con.CF_HDROP, header + body)
            self.wc.SetClipboardData(self.CF_DROPEFFECT, struct.pack("<I", 1))   # 1 = copy, not move
        self._write(fill)


def make_backend():
    system = platform.system()
    if system == "Linux":
        return LinuxBackend()
    if system == "Windows":
        try:
            return WindowsBackend()
        except ImportError:
            C.log("pywin32 not installed: syncing text only")
    return TextOnlyBackend()


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


class ClipboardSync:
    """Mixin for a Mesh: keeps the clipboard in step across connected machines.

    Call init_clipboard() in __init__, run watch_clipboard() in a thread, and let
    on_frame() route clipboard frames here. Needs the Mesh's cfg, links, peers,
    plan and notify().
    """

    CLIP_FRAMES = ("clip", "files_begin", "dir", "file_chunk", "files_end")

    def init_clipboard(self):
        self.backend = make_backend()
        self.received_dir = C.RECEIVED_DIR               # fixed per instance
        self.last_sig = None
        self.clip_lock = threading.Lock()

    def on_frame(self, link, header, payload):
        kind = header.get("type")
        if kind == "clip":
            self.on_remote_clip(link.peer_id, header, payload)
        elif kind in self.CLIP_FRAMES:
            self.on_remote_files(link, header, payload)

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
                C.log(f"clipboard read failed: {exc}")
                clip = None
            if clip:
                with self.clip_lock:
                    changed = clip.sig != self.last_sig
                    if changed:
                        self.last_sig = clip.sig
                if changed and not self.cfg.paused and self.links:
                    self.broadcast(clip)
            time.sleep(C.POLL_EVERY)

    def broadcast(self, clip: Clip):
        links = [link for link in self.links.values() if link.alive]
        if clip.kind == "text":
            if not clip.text:
                return
            data = clip.text.encode("utf-8")
            if len(data) > C.MAX_CLIP_BYTES:
                C.log("text too large to send")
                return
            for link in links:
                link.send({"type": "clip", "mime": "text/plain;charset=utf-8"}, data)
        elif clip.kind == "image":
            if self.features().get("images") is False:
                return
            if len(clip.png) > C.MAX_CLIP_BYTES:
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
            if total > C.FILES_MAX_TOTAL:
                self.notify(f"Not sending {human_size(total)}: that's over the {human_size(C.FILES_MAX_TOTAL)} limit.")
                return
            for link in links:
                threading.Thread(target=self._send_files, args=(link, clip.paths, total), daemon=True).start()

    def _send_files(self, link, paths, total):
        fid = str(uuid.uuid4())
        link.send({"type": "files_begin", "id": fid, "items": [os.path.basename(p.rstrip("/\\")) for p in paths],
                   "total": total})

        def send_file(full, rel):
            offset = 0
            try:
                with open(full, "rb") as fh:
                    while link.alive:
                        chunk = fh.read(C.CHUNK_BYTES)
                        eof = len(chunk) < C.CHUNK_BYTES
                        link.send({"type": "file_chunk", "id": fid, "path": rel, "offset": offset, "eof": eof}, chunk)
                        offset += len(chunk)
                        if eof:
                            break
            except OSError as exc:
                C.log(f"skipped {full}: {exc}")

        for p in paths:
            p = p.rstrip("/\\")
            base = os.path.dirname(p)
            if os.path.isdir(p):
                for root, dirs, files in os.walk(p):
                    rel_root = os.path.relpath(root, base).replace(os.sep, "/")
                    link.send({"type": "dir", "id": fid, "path": rel_root})
                    for f in files:
                        send_file(os.path.join(root, f), rel_root + "/" + f)
            elif os.path.isfile(p):
                send_file(p, os.path.basename(p))
        link.send({"type": "files_end", "id": fid})
        name = self.peers.get(link.peer_id, {}).get("name", "another machine")
        C.log(f"sent {len(paths)} item(s), {human_size(total)}, to {name}")

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
            C.log(f"can't write the clipboard: {exc}")

    def on_remote_files(self, link, header, payload):
        kind, fid = header.get("type"), str(header.get("id", ""))
        if kind == "files_begin":
            if self.cfg.paused:
                return
            dest = self.received_dir / time.strftime("%Y-%m-%d %H%M%S")
            n = 1
            while dest.exists():
                n += 1
                dest = self.received_dir / (time.strftime("%Y-%m-%d %H%M%S") + f" ({n})")
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
                    C.log(f"can't put received files on the clipboard: {exc}")
            name = self.peers.get(link.peer_id, {}).get("name", "another machine")
            self.notify(f"Received {len(paths)} item(s), {human_size(rx['total'])}, from {name}. "
                        f"Paste in your file manager, or find them in {rx['dest']}")
