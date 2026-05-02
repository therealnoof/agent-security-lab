#!/usr/bin/env bash
# =============================================================
#  agent-security-lab — Ubuntu 22.04 lab-node bootstrap
# =============================================================
#  Brings a fresh Ubuntu 22.04 (or 24.04) host to the point
#  where a learner can `git clone` this repo and run
#  `docker compose run --rm triage`.
#
#  What this script does (idempotent — safe to re-run):
#    1. Update apt cache and install core utilities
#    2. Install Docker Engine + Compose plugin from the
#       official Docker apt repository (NOT the snap)
#    3. Add the invoking user to the `docker` group so they
#       can run docker without sudo
#    4. Pre-pull the third-party images this lab uses so the
#       first `docker compose up` is fast even on flaky WiFi
#    5. Verify the install end-to-end with `hello-world`
#
#  What it deliberately does NOT do:
#    - Run `apt upgrade` (can break long-lived hosts)
#    - Install Python, Node, kubectl, helm, etc. (not needed —
#      everything else runs in containers)
#    - Configure ufw / firewall (this lab needs no inbound
#      ports from the internet; leave host firewall to the
#      operator)
#    - Clone this repo (the operator chooses where it lives)
#
#  Usage (from a fresh Ubuntu host):
#    curl -fsSL <raw-url>/scripts/setup-ubuntu-22.sh -o setup.sh
#    bash setup.sh
#
#  Or, if you have already cloned the repo:
#    bash scripts/setup-ubuntu-22.sh
#
#  After it finishes, log out and back in (so the docker
#  group membership takes effect) and follow SETUP.md §A.
# =============================================================

set -euo pipefail

# --- Pretty logging ----------------------------------------
log()  { printf '\033[1;34m[setup]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ ok ]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }

# --- Pre-flight --------------------------------------------
[[ "$(uname -s)" == "Linux" ]] || die "This script is for Linux (Ubuntu 22.04/24.04 specifically)."

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}:${VERSION_ID:-}" in
    ubuntu:22.04|ubuntu:24.04) ok "Detected Ubuntu ${VERSION_ID}";;
    ubuntu:*)                  warn "Ubuntu ${VERSION_ID} is not officially tested; proceeding anyway.";;
    *)                         die  "Unsupported distro: ${ID:-unknown}. This script targets Ubuntu.";;
  esac
else
  die "Cannot read /etc/os-release — is this really Ubuntu?"
fi

# Decide whether we need sudo. Inside cloud-init / Packer / `sudo -i`
# the script often runs as root with USER and SUDO_USER unset, so we
# need careful fallbacks to keep `set -u` happy.
if [[ $EUID -eq 0 ]]; then
  SUDO=""
  # Preference order: the user who invoked sudo, the current $USER,
  # then the standard Ubuntu cloud user.
  TARGET_USER="${SUDO_USER:-${USER:-ubuntu}}"
  # If that user does not actually exist on this host, fall back to
  # root and we will skip the docker group step entirely.
  if ! id -u "$TARGET_USER" >/dev/null 2>&1; then
    warn "User '${TARGET_USER}' does not exist on this host; docker group step will be skipped."
    TARGET_USER="root"
  fi
else
  SUDO="sudo"
  TARGET_USER="${USER:-$(id -un)}"
  command -v sudo >/dev/null 2>&1 || die "sudo is required when not running as root"
fi

log "Target user for docker group membership: ${TARGET_USER}"

# --- Step 1: apt update + core utilities -------------------
log "Updating apt cache and installing core utilities…"
$SUDO apt-get update -y
$SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y \
  ca-certificates \
  curl \
  git \
  gnupg \
  jq \
  lsb-release
ok "Core utilities installed."

# --- Step 2: Docker Engine + Compose plugin ----------------
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  ok "Docker + Compose already installed: $(docker --version), $(docker compose version | head -n1)"
else
  log "Installing Docker Engine + Compose plugin from the official Docker apt repo…"

  # Remove any old/conflicting docker packages from the
  # default Ubuntu archive (these break the official repo).
  for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do
    $SUDO apt-get remove -y "$pkg" >/dev/null 2>&1 || true
  done

  # Add Docker's GPG key.
  $SUDO install -m 0755 -d /etc/apt/keyrings
  if [[ ! -s /etc/apt/keyrings/docker.asc ]]; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
      $SUDO tee /etc/apt/keyrings/docker.asc >/dev/null
    $SUDO chmod a+r /etc/apt/keyrings/docker.asc
  fi

  # Add the apt source.
  ARCH="$(dpkg --print-architecture)"
  CODENAME="$(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")"
  echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${CODENAME} stable" | \
    $SUDO tee /etc/apt/sources.list.d/docker.list >/dev/null

  $SUDO apt-get update -y
  $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin

  ok "Docker installed: $(docker --version)"
  ok "Compose plugin installed: $(docker compose version | head -n1)"
fi

# --- Step 3: docker group membership -----------------------
if [[ "$TARGET_USER" == "root" ]]; then
  ok "Running as root with no non-root user identified; skipping docker group membership."
elif id -nG "$TARGET_USER" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
  ok "User '${TARGET_USER}' is already in the docker group."
else
  log "Adding '${TARGET_USER}' to the docker group…"
  $SUDO usermod -aG docker "$TARGET_USER"
  warn "Group change requires a re-login (or 'newgrp docker') to take effect."
fi

# Make sure dockerd is running and enabled at boot.
$SUDO systemctl enable --now docker >/dev/null
ok "Docker service is running and enabled at boot."

# --- Step 4: pre-pull lab images ---------------------------
log "Pre-pulling lab images (warms the cache so first compose-up is fast)…"
IMAGES=(
  "quay.io/keycloak/keycloak:25.0"
  "postgres:16-alpine"
  "python:3.11-slim"
)
for img in "${IMAGES[@]}"; do
  log "  pulling ${img}"
  $SUDO docker pull "$img"
done
ok "All lab images pulled."

# --- Step 5: smoke test ------------------------------------
log "Running 'hello-world' to verify the install…"
if $SUDO docker run --rm hello-world >/dev/null; then
  ok "Docker is working."
else
  die "hello-world failed — investigate before continuing."
fi

# --- Done --------------------------------------------------
cat <<EOF

──────────────────────────────────────────────────────────────
  Ubuntu lab-node bootstrap complete.

  Next steps:
    1. Log out and back in (so docker group membership takes
       effect for ${TARGET_USER}). Or, in this shell only:
         newgrp docker

    2. Clone the lab repo and follow SETUP.md §A:
         git clone <repo-url> agent-security-lab
         cd agent-security-lab
         cp .env.example .env       # fill in CALYPSOAI_*
         docker compose build triage
         docker compose run --rm triage

  Versions installed:
    $(docker --version)
    $(docker compose version | head -n1)
──────────────────────────────────────────────────────────────
EOF
