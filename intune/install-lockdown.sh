#!/bin/bash
# install-lockdown.sh - Intune-friendly installer for MacGSALockdown.
#
# Intune (Microsoft Intune > Devices > macOS > Shell scripts) runs this as
# root, one-shot, with no user UI. Idempotent: safe to re-run.
#
# What it does:
#   1. Verifies macOS + root.
#   2. Verifies the GSA Client is installed (otherwise no-op exits cleanly so
#      Intune doesn't keep flapping on machines where GSA was never deployed).
#   3. Copies the lockdown scripts to /usr/local/libexec/macgsa-lockdown/.
#   4. Invokes `macgsa-lockdown.sh lockdown`, which applies schg + deny ACEs
#      and installs the guardian LaunchDaemon.
#
# Exit codes:
#   0  success or skipped (GSA not installed)
#   2  precondition failure (not root, not macOS)
#   1  lockdown step failed; check /var/log/macgsa-lockdown.log

set -u

INSTALL_BIN_DIR="/usr/local/libexec/macgsa-lockdown"
GSA_BASE_DIR="/Applications/GlobalSecureAccessClient"

log() { echo "[install-lockdown] $*"; /usr/bin/logger -t macgsa-install -- "$*" 2>/dev/null || true; }

if [ "$(/usr/bin/id -u)" -ne 0 ]; then
    log "ERROR: must run as root"; exit 2
fi
if [ "$(/usr/bin/uname -s)" != "Darwin" ]; then
    log "ERROR: macOS only"; exit 2
fi

if [ ! -d "${GSA_BASE_DIR}" ]; then
    log "GSA Client is not installed at ${GSA_BASE_DIR}; nothing to lock down. Exiting 0."
    exit 0
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# In an Intune deployment the bin/ contents are bundled alongside this script.
# Support both layouts: sibling bin/ folder or flat (everything in same dir).
SRC_DIR=""
if [ -f "${SCRIPT_DIR}/../bin/macgsa-lockdown.sh" ]; then
    SRC_DIR="$(cd -- "${SCRIPT_DIR}/../bin" && pwd -P)"
elif [ -f "${SCRIPT_DIR}/macgsa-lockdown.sh" ]; then
    SRC_DIR="${SCRIPT_DIR}"
else
    log "ERROR: cannot locate macgsa-lockdown.sh next to installer"
    exit 1
fi

/bin/mkdir -p "${INSTALL_BIN_DIR}"
/usr/bin/install -m 0755 -o root -g wheel "${SRC_DIR}/macgsa-lockdown.sh" "${INSTALL_BIN_DIR}/macgsa-lockdown.sh"
/usr/bin/install -m 0644 -o root -g wheel "${SRC_DIR}/lib-common.sh"     "${INSTALL_BIN_DIR}/lib-common.sh"

log "Files staged in ${INSTALL_BIN_DIR}. Invoking lockdown..."
if /bin/bash "${INSTALL_BIN_DIR}/macgsa-lockdown.sh" lockdown; then
    log "Lockdown applied successfully."
    exit 0
else
    rc=$?
    log "Lockdown returned rc=${rc}; see /var/log/macgsa-lockdown.log"
    exit ${rc}
fi
