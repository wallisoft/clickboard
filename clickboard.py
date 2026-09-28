#!/usr/bin/env python3
"""
Clickboard - the clipboard that follows you between machines.

This file is the app: tray icon, settings window and dock/launcher control.
The engine (discovery, TLS, clipboard sync) lives in clickboard_core, which
other Wallisoft products build on too.
"""
import shutil
import socket
import subprocess
import sys
import threading
import webbrowser

import pystray
from PIL import Image, ImageDraw

from clickboard_core.protocol import reuse_or_exclusive
from clickboard_core import (MIN_PASSPHRASE, SIGNUP_EMAIL, ClipboardSync, Config, Mesh,
                             log, set_app, signup_info)

VERSION = "2.6.0"
SIGNUP_URL = "https://clickboard.eur.bz/#signup"
CONTROL_PORT = 47801      # localhost only: lets the launcher talk to a running copy

COLOUR_OK = (34, 197, 94, 255)        # green: syncing with at least one machine
COLOUR_OFF = (249, 115, 22, 255)      # orange: not connected (or needs attention)
COLOUR_PAUSED = (249, 115, 22, 255)   # orange too: paused by you (menu says which)


class App(ClipboardSync, Mesh):
    """Clickboard: a Mesh with clipboard sync, a tray icon and a settings window."""

    def __init__(self):
        Mesh.__init__(self, Config.load(), service="clickboard")
        self.init_clipboard()
        self.icon = None
        self._settings_open = False

    # ---- UI plumbing ----
    def notify(self, msg):
        log(msg)
        try:
            if shutil.which("notify-send"):
                subprocess.Popen(["notify-send", "Clickboard", msg])
            elif self.icon:
                self.icon.notify(msg, "Clickboard")
        except Exception:
            pass

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
            reuse_or_exclusive(cs)
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
        self.stop()
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
        self.start()                                   # Mesh: discovery, TLS, links
        for target in (self.watch_clipboard, self.control_loop):
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
                ttk.Entry(box, textvariable=var, width=26, state="readonly", font="TkFixedFont").pack(side="left")
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
            r = self.app.remove_device(device_id)
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
    set_app("Clickboard", VERSION)
    app = App()
    if cmd in ("pause", "resume"):
        app.cfg.paused = cmd == "pause"
        app.cfg.save()
    app.run()


if __name__ == "__main__":
    main()
