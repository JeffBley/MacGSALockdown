#!/bin/bash
# uninstall-lockdown.sh - Break-glass / pre-upgrade unlock script.
#
# Push this from Intune (Devices > macOS > Shell scripts) BEFORE deploying a
# new GSA Client pkg, or as a remediation when the lockdown needs to be
# removed. Idempotent: safe to re-run.
#
# What it does:
#   1. Invokes `macgsa-lockdown.sh reset` (clears schg, removes deny ACEs,
#      bootouts + removes the guardian LaunchDaemon).
#   2. Removes the staged scripts at /usr/local/libexec/macgsa-lockdown/.
#
# After this runs, GSA can be upgraded by the standard installer. Re-deploy
# install-lockdown.sh afterwards.

set -u

INSTALL_BIN_DIR="/usr/local/libexec/macgsa-lockdown"
INSTALL_LIB_DIR="/Library/Application Support/Microsoft/GSA-Lockdown"

log() { echo "[uninstall-lockdown] $*"; /usr/bin/logger -t macgsa-uninstall -- "$*" 2>/dev/null || true; }

if [ "$(/usr/bin/id -u)" -ne 0 ]; then
    log "ERROR: must run as root"; exit 2
fi

if [ -x "${INSTALL_BIN_DIR}/macgsa-lockdown.sh" ]; then
    log "Running reset via staged script..."
    /bin/bash "${INSTALL_BIN_DIR}/macgsa-lockdown.sh" reset || log "reset returned non-zero (continuing)"
else
    log "Staged script not present; nothing to reset."
fi

/bin/rm -rf "${INSTALL_BIN_DIR}"
# Leave INSTALL_LIB_DIR in place: it may hold the kill-switch file the
# operator deliberately created. Only remove the factory-state snapshot.
/bin/rm -f "${INSTALL_LIB_DIR}/factory-state.json"

log "Uninstall complete. GSA is upgrade-ready."
exit 0
