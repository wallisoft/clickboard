# Clickboard

**The clipboard that follows you between machines.** Copy on one computer, paste on another: text, images, files and whole folders, across Linux and Windows on your local network.

No send dialogs, no shared folders. Just Ctrl+C here and Ctrl+V there.

## Features

- **Text, images, files and folders.** Copy a folder in your file manager, then paste it in the file manager on your other machine.
- **Linux and Windows 11**, in any combination.
- **Finds your machines by itself.** No IP addresses, no pairing codes.
- **Private by design.** Machines connect directly to each other over encrypted TLS 1.3. What you copy never touches our servers.
- **Lives in your tray.** A dot shows the status: green is syncing, orange is not. Pause from the tray or your dock.

## Two ways to connect

**Tiny-Web key (recommended).** Sign up once for a free [Tiny-Web](https://tiny-web.uk) key and enter it on each machine. Your machines find each other through your account and only trust each other's certificates, so it's safe on any network. The free tier covers 3 machines.

**Shared passphrase (no signup).** Choose the same passphrase on each machine, at least 8 characters (the **Generate** button makes a good four-word one). Machines on the same network with the same passphrase connect automatically. Good for quickly sharing with someone you've just met.

## Install

### Linux (Ubuntu 24.04 and similar)

```
curl -fsSL https://raw.githubusercontent.com/wallisoft/clickboard/main/install.sh | bash
```

The installer asks for your password once, to add the clipboard and tray tools it needs and to open its ports if your firewall is on. Clickboard then starts automatically when you log in.

### Windows 10 and 11

In PowerShell:

```
irm https://raw.githubusercontent.com/wallisoft/clickboard/main/install.ps1 | iex
```

It installs Python if needed, sets Clickboard up in your user profile, adds it to the Start menu and to start at sign-in, and asks once for admin permission to open its ports on private networks.

Run either command again at any time to update.

## How it works

- Each machine creates its own TLS certificate on first run.
- **Key mode:** machines register their certificate and local address with Tiny-Web, and learn about your other machines. They then connect directly and verify each other's certificates. Other people's machines, even on the same Wi-Fi, can't connect.
- **Passphrase mode:** machines announce themselves on the local network, signed with a key derived from your passphrase. Only machines that can prove they know the passphrase are trusted.
- Changes are pushed the moment you copy. Received files are saved in `~/Clickboard/Received/` and placed on the clipboard, ready to paste.

Ports: TCP 47800 (machine to machine), UDP 47802 (passphrase-mode discovery), TCP 47801 (local only, for the tray and dock).

## Privacy

Tiny-Web stores each machine's name, local network address and public certificate, so your machines can find each other. It never sees anything you copy.

- [Tiny-Web Terms of Service](https://tiny-web.uk/terms.php)
- [Tiny-Web Privacy Policy](https://tiny-web.uk/privacy.php)

## Licence

Clickboard is **free for individuals and small businesses** under the [PolyForm Small Business License 1.0.0](LICENSE). Larger organisations need a commercial licence: see [COMMERCIAL.md](COMMERCIAL.md).

The source is open to read, and contributions are welcome. A macOS port would be especially lovely. See [CONTRIBUTING.md](CONTRIBUTING.md): contributors sign a short [CLA](CLA.md), because Wallisoft also builds commercial products on Clickboard's core.

---

Built by [Wallisoft](https://github.com/wallisoft) with Claude · Part of the [Tiny-Web](https://tiny-web.uk) family · Made in Eastbourne
