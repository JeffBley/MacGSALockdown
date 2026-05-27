#!/bin/bash
# Common helpers for macgsa-lockdown.sh and the guardian.
# Shellcheck shell=bash

set -u

# ---- Constants -------------------------------------------------------------

# Paths covered by the lockdown. Order matters for chflags recursion.
GSA_BASE_DIR="/Applications/GlobalSecureAccessClient"
GSA_APP="${GSA_BASE_DIR}/Global Secure Access Client.app"
GSA_UNINSTALLER_APP="${GSA_BASE_DIR}/Uninstall Global Secure Access Client.app"

GSA_LOCKDOWN_PATHS=(
    "${GSA_APP}"
    "${GSA_UNINSTALLER_APP}"
)

# Bundle / pkg identifiers (from `pkgutil --pkg-info com.microsoft.globalsecureaccess`
# and `systemextensionsctl list`).
GSA_PKG_ID="com.microsoft.globalsecureaccess"
GSA_SYSEXT_BUNDLE_ID="com.microsoft.globalsecureaccess.tunnel"
GSA_TEAM_ID="UBF8T346G9"

# Kill-switch (parity with Windows IsAntiTamperingDisabled). Presence -> guardian
# skips re-assertion. Creating it requires root.
GSA_KILLSWITCH_DIR="/Library/Application Support/Microsoft/GSA-Lockdown"
GSA_KILLSWITCH_FILE="${GSA_KILLSWITCH_DIR}/IsAntiTamperingDisabled"

# Tool install paths.
INSTALL_BIN_DIR="/usr/local/libexec/macgsa-lockdown"
INSTALL_LIB_DIR="/Library/Application Support/Microsoft/GSA-Lockdown"
GUARDIAN_PLIST_LABEL="com.contoso.gsaguardian"
GUARDIAN_PLIST_PATH="/Library/LaunchDaemons/${GUARDIAN_PLIST_LABEL}.plist"
FACTORY_STATE_PATH="${INSTALL_LIB_DIR}/factory-state.json"

# Logs.
LOG_DIR="/var/log"
TOOL_LOG="${LOG_DIR}/macgsa-lockdown.log"
GUARDIAN_LOG="${LOG_DIR}/macgsa-guardian.log"
BACKUP_DIR="${LOG_DIR}"   # snapshots written as macgsa-lockdown-backup-<mode>-<ts>.json

# Desired ACE applied to lockdown roots (recursive). Denies all admin-side
# mutations even though admins remain owner. Allows execute/read so the app
# still launches and the system extension still loads.
GSA_DENY_ACE='everyone deny delete,write,append,writeattr,writeextattr,chown,delete_child'

# Desired file flag.
GSA_DESIRED_FLAG="schg"

# ---- Logging ---------------------------------------------------------------

_log() {
    local level="$1"; shift
    local msg="$*"
    local ts; ts="$(date +'%Y-%m-%dT%H:%M:%S%z')"
    local line="${ts} [${level}] ${msg}"
    echo "${line}"
    # Best-effort file log; ignore if not writable (e.g. running as non-root query).
    if [ -w "${TOOL_LOG}" ] || ( [ ! -e "${TOOL_LOG}" ] && [ -w "${LOG_DIR}" ] ); then
        echo "${line}" >> "${TOOL_LOG}" 2>/dev/null || true
    fi
    # Mirror to unified log so it shows up in Console.app.
    # NOTE: macOS ships bash 3.2 — avoid bash 4+ ${var,,} lowercasing.
    local level_lc
    level_lc="$(printf '%s' "$level" | tr '[:upper:]' '[:lower:]')"
    /usr/bin/logger -t macgsa-lockdown -p "user.${level_lc}" -- "${msg}" 2>/dev/null || \
        /usr/bin/logger -t macgsa-lockdown -- "${msg}" 2>/dev/null || true
}

log_info()  { _log INFO    "$@"; }
log_warn()  { _log WARNING "$@"; }
log_error() { _log ERROR   "$@"; }

# ---- Guards ----------------------------------------------------------------

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "Must be run as root (use sudo). Aborting."
        exit 2
    fi
}

require_macos() {
    if [ "$(uname -s)" != "Darwin" ]; then
        log_error "macOS only. Detected: $(uname -s)"
        exit 2
    fi
    local ver_major
    ver_major="$(/usr/bin/sw_vers -productVersion | cut -d. -f1)"
    if [ "${ver_major}" -lt 14 ]; then
        log_warn "macOS 14+ is supported; detected ${ver_major}. Continuing best-effort."
    fi
}

killswitch_active() {
    [ -f "${GSA_KILLSWITCH_FILE}" ]
}

# ---- State inspection ------------------------------------------------------

# Print the schg state of a path: "set" | "unset" | "missing".
flag_state() {
    local p="$1"
    if [ ! -e "${p}" ]; then
        echo "missing"; return
    fi
    if /usr/bin/stat -f '%Sf' "${p}" 2>/dev/null | /usr/bin/grep -q 'schg'; then
        echo "set"
    else
        echo "unset"
    fi
}

# Print whether the desired deny ACE is present.
ace_state() {
    local p="$1"
    if [ ! -e "${p}" ]; then echo "missing"; return; fi
    if /bin/ls -lde "${p}" 2>/dev/null | /usr/bin/grep -qi 'deny.*delete'; then
        echo "present"
    else
        echo "absent"
    fi
}

# Classify a single path's overall state.
overall_state() {
    local p="$1"
    local f a
    f="$(flag_state "$p")"
    a="$(ace_state  "$p")"
    if [ "$f" = "missing" ]; then echo "Missing"; return; fi
    if [ "$f" = "set" ] && [ "$a" = "present" ]; then echo "Lockdown"; return; fi
    if [ "$f" = "unset" ] && [ "$a" = "absent" ];  then echo "Default";  return; fi
    echo "Partial"
}

# System extension presence (active+enabled => Active, present-but-not => Stopped, else Missing).
sysext_state() {
    local out
    out="$(/usr/bin/systemextensionsctl list 2>/dev/null | /usr/bin/grep -F "${GSA_SYSEXT_BUNDLE_ID}" | /usr/bin/head -n1)"
    if [ -z "${out}" ]; then echo "Missing"; return; fi
    if echo "${out}" | /usr/bin/grep -q 'activated enabled'; then echo "Active"
    else echo "Stopped"
    fi
}

guardian_state() {
    if [ ! -f "${GUARDIAN_PLIST_PATH}" ]; then echo "NotInstalled"; return; fi
    if /bin/launchctl print "system/${GUARDIAN_PLIST_LABEL}" >/dev/null 2>&1; then
        echo "Loaded"
    else
        echo "Installed-NotLoaded"
    fi
}
