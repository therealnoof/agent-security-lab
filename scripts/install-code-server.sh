#!/usr/bin/env bash
# =============================================================
#  agent-security-lab — install-code-server.sh
# =============================================================
#  Installs code-server (browser-based VS Code from Coder) on
#  this Ubuntu host so learners can read and edit lab code in
#  a remote browser instead of via SSH + terminal editor.
#
#  Defaults:
#    - Listens on 0.0.0.0:8443 (HTTPS, self-signed cert)
#    - Runs as the 'ubuntu' user
#    - Auto-starts on boot via systemd (code-server@ubuntu.service)
#    - Workspace lives at /home/ubuntu/agent-security-lab
#    - Random password generated and printed at end (or supply
#      CODE_SERVER_PASSWORD to set your own)
#
#  Why port 8443? The lab already binds 8080 (Keycloak),
#  8000 (MCP), 9100 (Comms). 8443 is HTTPS-conventional and
#  free, and most cloud security groups already allow it.
#
#  Usage:
#    sudo bash scripts/install-code-server.sh
#    sudo CODE_SERVER_PASSWORD='your-pick' bash scripts/install-code-server.sh
#    sudo CODE_SERVER_PORT=9443 bash scripts/install-code-server.sh
#
#  Idempotent: re-running re-applies config and restarts the
#  service. The password is regenerated only if you don't set
#  CODE_SERVER_PASSWORD.
#
#  After install:
#    1. Open the printed URL (https://<host>:8443) in a browser.
#    2. Accept the self-signed cert warning.
#    3. Enter the printed password.
#    4. File → Open Folder → /home/ubuntu/agent-security-lab
#
#  Don't forget the cloud security group / firewall — port
#  8443 must be reachable from your laptop.
# =============================================================

set -euo pipefail

# --- Tunable defaults --------------------------------------
PORT="${CODE_SERVER_PORT:-8443}"
TARGET_USER="${CODE_SERVER_USER:-ubuntu}"
LAB_DIR="${LAB_DIR:-/home/ubuntu/agent-security-lab}"
PASSWORD="${CODE_SERVER_PASSWORD:-}"

# --- Pretty logging ----------------------------------------
log()  { printf '\033[1;34m[code-server]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ ok ]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }

# --- Pre-flight --------------------------------------------
[[ $EUID -eq 0 ]] || die "Run with sudo or as root (we manage a systemd service)."

if ! id -u "$TARGET_USER" >/dev/null 2>&1; then
  die "User '$TARGET_USER' does not exist on this host."
fi

USER_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)
[[ -d "$USER_HOME" ]] || die "Home directory for $TARGET_USER not found: $USER_HOME"

# --- Step 1: install code-server ---------------------------
if ! command -v code-server >/dev/null 2>&1; then
  log "Installing code-server via the official Coder script…"
  curl -fsSL https://code-server.dev/install.sh | sh
else
  ok "code-server already installed: $(code-server --version | head -n1)"
fi

# --- Step 2: write config.yaml -----------------------------
CONFIG_DIR="$USER_HOME/.config/code-server"
mkdir -p "$CONFIG_DIR"

if [[ -z "$PASSWORD" ]]; then
  PASSWORD="$(openssl rand -hex 16)"
  log "Generated random password (override with CODE_SERVER_PASSWORD)."
fi

# Backup any prior config so the operator can recover the
# previous password if they didn't capture this one.
if [[ -f "$CONFIG_DIR/config.yaml" ]]; then
  cp "$CONFIG_DIR/config.yaml" "$CONFIG_DIR/config.yaml.prev"
fi

cat > "$CONFIG_DIR/config.yaml" <<EOF
bind-addr: 0.0.0.0:$PORT
auth: password
password: $PASSWORD
cert: true
EOF

chown -R "$TARGET_USER":"$TARGET_USER" "$USER_HOME/.config"
chmod 600 "$CONFIG_DIR/config.yaml"
ok "Wrote $CONFIG_DIR/config.yaml (mode 600)."

# --- Step 3: enable + (re)start systemd service ------------
log "Enabling and restarting code-server@${TARGET_USER}.service…"
systemctl daemon-reload
systemctl enable "code-server@${TARGET_USER}" >/dev/null
systemctl restart "code-server@${TARGET_USER}"

# Wait briefly for the listener to come up
sleep 2
if systemctl is-active --quiet "code-server@${TARGET_USER}"; then
  ok "Service is active."
else
  warn "Service did not come up; check: journalctl -u code-server@${TARGET_USER} --no-pager -n 50"
fi

# --- Step 4: figure out a reachable host -------------------
# Try EC2 IMDS first, then fall back to the first non-loopback
# IP. If both fail, just say <host>.
EXT_IP="$(
  curl -fsS --max-time 3 http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null \
    || hostname -I 2>/dev/null | awk '{print $1}' \
    || echo "<host>"
)"

# --- Final notice ------------------------------------------
cat <<NOTICE

──────────────────────────────────────────────────────────────
  code-server is running.

  URL       https://${EXT_IP}:${PORT}
  Password  ${PASSWORD}

  Steps after first login:
    1. Accept the self-signed cert warning in your browser.
    2. Enter the password above.
    3. File → Open Folder → ${LAB_DIR}

  Cloud security group / firewall: open inbound TCP ${PORT}
  from your IP if you can't reach the URL.

  Service controls (run as root or with sudo):
    Status   systemctl status  code-server@${TARGET_USER}
    Restart  systemctl restart code-server@${TARGET_USER}
    Logs     journalctl -u code-server@${TARGET_USER} -f
    Stop     systemctl stop    code-server@${TARGET_USER}
    Disable  systemctl disable code-server@${TARGET_USER}

  Change password later:
    sudo nano ${CONFIG_DIR}/config.yaml
    sudo systemctl restart code-server@${TARGET_USER}
──────────────────────────────────────────────────────────────

NOTICE
