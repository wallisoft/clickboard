#!/usr/bin/env bash
#
# install.sh — sets up Clickboard for the current user.
#
# Usage:
#   Extract clickboard-latest.tar.gz and run the install.sh inside it:
#       tar xzf clickboard-latest.tar.gz && bash install.sh
#   — or run install.sh standalone and it'll fetch the package itself from
#   CLICKBOARD_PACKAGE_URL below (a Google Drive direct-download link).
#
#   Re-running this script is safe, and is also how you upgrade: files
#   sitting next to it (or freshly downloaded) always replace the
#   installed copy.
#
# Root handling, explicitly:
#   This script must NOT be run as root (no `sudo bash install.sh`,
#   no root shell). Your Python venv and ~/bin files need to be owned
#   by YOU, not root — a root-owned venv breaks the moment you try to
#   use it as yourself afterwards.
#
#   It MAY need sudo for exactly two things: installing any missing
#   system packages (python3-venv, the GTK/AppIndicator tray bindings,
#   avahi-utils, openssh-server) and enabling the SSH service. Each of
#   those is called out below, individually, right before it happens
#   — you'll see exactly what's asking for your password and why.

set -euo pipefail

PACKAGE_URL="${CLICKBOARD_PACKAGE_URL:-https://drive.google.com/uc?export=download&id=1dVVqly5LGdfXshmj2RINPUdzVNn-bGSi}"
PROJECT_DIR="$HOME/projects/clickboard"
BIN_SHIM="$HOME/bin/clickboard"
SOURCE_FILES=(clickboard.py requirements.txt clickboard.desktop)
REQUIRED_PKGS=(python3-venv python3-gi gir1.2-ayatanaappindicator3-0.1 gir1.2-gtk-3.0 python3-tk xclip wl-clipboard libnotify-bin)

if [ "$(id -u)" -eq 0 ]; then
    echo "Don't run this whole script as root." >&2
    echo "It calls sudo itself for the specific steps that need it." >&2
    echo "Run it as your normal user instead:  bash install.sh" >&2
    exit 1
fi

echo "==> Installing Clickboard for $(whoami) into $PROJECT_DIR"
mkdir -p "$PROJECT_DIR"

# --- Source files -----------------------------------------------------------
# Prefer files shipped alongside this script (the normal tar.gz flow).
# Only fall back to downloading if they're not here.
src_dir="$(cd "$(dirname "${BASH_SOURCE[0]:-.}")" && pwd)"

have_local_source=1
for f in "${SOURCE_FILES[@]}"; do
    [ -f "$src_dir/$f" ] || have_local_source=0
done

if [ "$src_dir" = "$PROJECT_DIR" ]; then
    echo "==> Running from the install directory itself, using files in place"
elif [ "$have_local_source" -eq 1 ]; then
    echo "==> Copying Clickboard files from $src_dir"
    for f in "${SOURCE_FILES[@]}"; do
        cp "$src_dir/$f" "$PROJECT_DIR/"
    done
else
    echo "==> Downloading and extracting the package"
    tmp_pkg="$(mktemp /tmp/clickboard-package.XXXXXX.tar.gz)"
    curl -fsSL "$PACKAGE_URL" -o "$tmp_pkg"
    tar xzf "$tmp_pkg" -C "$PROJECT_DIR"
    rm -f "$tmp_pkg"
fi

for f in "${SOURCE_FILES[@]}"; do
    if [ ! -f "$PROJECT_DIR/$f" ]; then
        echo "Missing $f in $PROJECT_DIR — the package looks incomplete." >&2
        exit 1
    fi
done
chmod +x "$PROJECT_DIR/clickboard.py"

# --- System packages --------------------------------------------------------
# Only touch apt if something is actually missing. If apt errors out because
# of something unrelated on this system (a broken repo, a half-configured
# kernel update), re-check: if our packages made it, carry on.
missing_pkgs() {
    local p
    for p in "${REQUIRED_PKGS[@]}"; do
        dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q "install ok installed" || echo "$p"
    done
}

MISSING=($(missing_pkgs))

echo ""
if [ ${#MISSING[@]} -eq 0 ]; then
    echo "==> System packages already installed, skipping apt"
else
    echo "==> Need sudo now: installing system packages: ${MISSING[*]}"
    echo "    (tray icon bindings for GNOME, network discovery, and SSH so"
    echo "    this machine can be reached by your other machines)"
    sudo apt update -qq || echo "    (apt update had errors, likely an unrelated broken repo; continuing)"
    sudo apt install -y "${MISSING[@]}" || echo "    (apt reported errors, checking whether our packages made it anyway)"

    STILL_MISSING=($(missing_pkgs))
    if [ ${#STILL_MISSING[@]} -ne 0 ]; then
        echo "" >&2
        echo "Couldn't install: ${STILL_MISSING[*]}" >&2
        echo "Something else on this system is blocking apt. Try 'sudo apt -f install'" >&2
        echo "to see what, fix that, then run this script again." >&2
        exit 1
    fi
    echo "==> System packages OK"
fi

# --- Firewall ---------------------------------------------------------------
# Clickboard machines talk to each other directly on TCP 47800 (TLS).
echo ""
if command -v ufw >/dev/null 2>&1 && sudo ufw status 2>/dev/null | grep -q "Status: active"; then
    echo "==> Need sudo now: allowing Clickboard (TCP 47800) through the firewall"
    sudo ufw allow 47800/tcp comment 'Clickboard' >/dev/null
    sudo ufw allow 47802/udp comment 'Clickboard local discovery' >/dev/null
else
    echo "==> Firewall not active, nothing to open"
fi

# Stop any running copy so the new version starts cleanly
pkill -f "$PROJECT_DIR/clickboard.py" 2>/dev/null || true

# --- Python venv ------------------------------------------------------------
echo ""
echo "==> Back to your own user from here — setting up the virtual environment"
python3 -m venv --system-site-packages "$PROJECT_DIR/venv"
"$PROJECT_DIR/venv/bin/pip" install --quiet -r "$PROJECT_DIR/requirements.txt"

# --- Launchers --------------------------------------------------------------
echo "==> Creating the launcher shim at $BIN_SHIM"
mkdir -p "$HOME/bin"
cat > "$BIN_SHIM" << SHIMEOF
#!/usr/bin/env bash
exec "$PROJECT_DIR/venv/bin/python3" "$PROJECT_DIR/clickboard.py" "\$@"
SHIMEOF
chmod +x "$BIN_SHIM"

echo "==> Installing the app-menu launcher"
mkdir -p "$HOME/.local/share/applications"
sed "s|Exec=.*|Exec=$BIN_SHIM|" "$PROJECT_DIR/clickboard.desktop" > "$HOME/.local/share/applications/clickboard.desktop"

echo "==> Starting Clickboard automatically when you log in"
mkdir -p "$HOME/.config/autostart"
cp "$HOME/.local/share/applications/clickboard.desktop" "$HOME/.config/autostart/"

echo ""
echo "Done. Run 'clickboard' (make sure ~/bin is on your PATH), or find it in your app launcher."
if ! echo "$PATH" | tr ':' '\n' | grep -qx "$HOME/bin"; then
    echo ""
    echo "Note: ~/bin isn't on your PATH yet. Add this to ~/.bashrc:"
    echo '  export PATH="$HOME/bin:$PATH"'
fi
