#!/bin/bash
# macgsa-lockdown.sh
#
# macOS port of the Windows GSA Lockdown tool (idMdev/GSALockdown).
# Hardens the Microsoft Entra Global Secure Access (GSA) Client on macOS so
# that a local admin cannot casually uninstall or delete it.
#
# Modes mirror the Windows tool's verbs:
#   query     (default) - read-only inspection of every in-scope object
#   lockdown  - apply schg + deny ACEs, install guardian LaunchDaemon
#   reset     - remove schg + deny ACEs, bootout guardian (required before upgrade)
#
# Threat model: stops casual tampering (drag-to-Trash, the bundled
# Uninstaller, plain `sudo rm`). It does NOT stop a determined root user who
# runs `sudo chflags noschg` first. For that, deploy the companion
# .mobileconfig profile via Intune; together they approximate the Windows
# DACL-based protection.
#
# Usage:
#   sudo ./macgsa-lockdown.sh                 # query
#   sudo ./macgsa-lockdown.sh lockdown
#   sudo ./macgsa-lockdown.sh reset
#   sudo ./macgsa-lockdown.sh query --verbose

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib-common.sh
. "${SCRIPT_DIR}/lib-common.sh"

VERBOSE=0
ACTION="query"

usage() {
    cat >&2 <<EOF
Usage: sudo $0 [query|lockdown|reset] [--verbose]

  query     Read-only state report (default). Does not require root for
            most checks, but root is recommended for complete output.
  lockdown  Apply schg + deny ACEs to GSA app + uninstaller, install the
            guardian LaunchDaemon. Requires root.
  reset    Remove schg + deny ACEs, bootout + remove the guardian. Required
            before any legitimate GSA upgrade. Requires root.

Options:
  --verbose, -v   Print per-object diff.
  --help,    -h   This message.
EOF
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            query|lockdown|reset) ACTION="$1" ;;
            --verbose|-v) VERBOSE=1 ;;
            --help|-h)    usage; exit 0 ;;
            *) echo "Unknown argument: $1" >&2; usage; exit 64 ;;
        esac
        shift
    done
}

# ---- Snapshot --------------------------------------------------------------

write_backup_snapshot() {
    local mode="$1"
    local ts; ts="$(date +'%Y%m%d-%H%M%S')"
    local out="${BACKUP_DIR}/macgsa-lockdown-backup-${mode}-${ts}.json"

    {
        printf '{\n'
        printf '  "timestamp": "%s",\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
        printf '  "host": "%s",\n' "$(/bin/hostname -s)"
        printf '  "runAs": "%s",\n' "$(/usr/bin/id -un)"
        printf '  "mode": "%s",\n' "${mode}"
        printf '  "paths": [\n'
        local first=1
        for p in "${GSA_LOCKDOWN_PATHS[@]}"; do
            [ ${first} -eq 1 ] || printf ',\n'
            first=0
            local owner perms flags acl sha
            if [ -e "${p}" ]; then
                owner="$(/usr/bin/stat -f '%Su:%Sg'        "${p}" 2>/dev/null)"
                perms="$(/usr/bin/stat -f '%Lp'            "${p}" 2>/dev/null)"
                flags="$(/usr/bin/stat -f '%Sf'            "${p}" 2>/dev/null)"
                acl="$(/bin/ls -lde "${p}" 2>/dev/null | /usr/bin/sed -n '2,$p' | /usr/bin/tr '\n' '|')"
                if [ -f "${p}" ]; then
                    sha="$(/usr/bin/shasum -a 256 "${p}" 2>/dev/null | /usr/bin/awk '{print $1}')"
                else
                    sha=""
                fi
            else
                owner=""; perms=""; flags=""; acl=""; sha=""
            fi
            printf '    {"path": %s, "owner": "%s", "perms": "%s", "flags": "%s", "acl": "%s", "sha256": "%s"}' \
                "$(printf '%s' "${p}" | /usr/bin/python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))' 2>/dev/null || printf '"%s"' "${p}")" \
                "${owner}" "${perms}" "${flags}" "${acl}" "${sha}"
        done
        printf '\n  ]\n}\n'
    } > "${out}"

    log_info "Snapshot written: ${out}"
}

# ---- Query mode ------------------------------------------------------------

action_query() {
    printf '\n=== macgsa-lockdown query — %s ===\n' "$(date)"
    printf 'Host: %s   User: %s   macOS: %s\n\n' \
        "$(/bin/hostname -s)" "$(/usr/bin/id -un)" "$(/usr/bin/sw_vers -productVersion)"

    printf '%-60s  %-8s  %-8s  %-10s\n' "PATH" "FLAG" "DENY-ACE" "OVERALL"
    printf -- '-%.0s' {1..96}; printf '\n'
    for p in "${GSA_LOCKDOWN_PATHS[@]}"; do
        printf '%-60s  %-8s  %-8s  %-10s\n' \
            "${p}" "$(flag_state "$p")" "$(ace_state "$p")" "$(overall_state "$p")"
    done

    printf '\nSystem extension (%s): %s\n' "${GSA_SYSEXT_BUNDLE_ID}" "$(sysext_state)"
    printf 'Guardian LaunchDaemon (%s): %s\n' "${GUARDIAN_PLIST_LABEL}" "$(guardian_state)"
    if killswitch_active; then
        printf 'Kill-switch: ACTIVE (guardian will NOT re-assert)\n'
    else
        printf 'Kill-switch: inactive\n'
    fi
    printf '\n'
}

# ---- Lockdown / Reset apply ------------------------------------------------

apply_lockdown_path() {
    local p="$1"
    if [ ! -e "${p}" ]; then
        log_warn "Skipping (missing): ${p}"
        return
    fi

    # Strip any existing ACL first to ensure idempotency.
    /bin/chmod -RN "${p}" 2>/dev/null || true

    # Apply deny ACE to the root of the bundle (covers descendants on macOS
    # via inheritance flags; we also apply recursively below for robustness).
    if ! /bin/chmod +a "${GSA_DENY_ACE}" "${p}" 2>/dev/null; then
        log_warn "chmod +a failed on ${p}"
    fi

    # Apply schg recursively. This is the primary defense.
    if ! /usr/bin/chflags -R "${GSA_DESIRED_FLAG}" "${p}" 2>/dev/null; then
        log_error "chflags ${GSA_DESIRED_FLAG} failed on ${p}"
        return 1
    fi

    log_info "Lockdown applied: ${p} (flag=$(flag_state "$p"), ace=$(ace_state "$p"))"
}

reset_path() {
    local p="$1"
    if [ ! -e "${p}" ]; then
        log_warn "Skipping (missing): ${p}"
        return
    fi
    /usr/bin/chflags -R noschg "${p}" 2>/dev/null || log_warn "chflags noschg failed on ${p}"
    /bin/chmod -RN "${p}" 2>/dev/null || true
    log_info "Reset: ${p} (flag=$(flag_state "$p"), ace=$(ace_state "$p"))"
}

# ---- Guardian install / remove --------------------------------------------

install_guardian() {
    /bin/mkdir -p "${INSTALL_BIN_DIR}"
    /bin/mkdir -p "${INSTALL_LIB_DIR}"

    # Copy this script + lib to a stable location the LaunchDaemon can call.
    /usr/bin/install -m 0755 -o root -g wheel "${SCRIPT_DIR}/macgsa-lockdown.sh" "${INSTALL_BIN_DIR}/macgsa-lockdown.sh"
    /usr/bin/install -m 0644 -o root -g wheel "${SCRIPT_DIR}/lib-common.sh"     "${INSTALL_BIN_DIR}/lib-common.sh"

    # Write the LaunchDaemon plist.
    /bin/cat > "${GUARDIAN_PLIST_PATH}" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${GUARDIAN_PLIST_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>${INSTALL_BIN_DIR}/macgsa-lockdown.sh</string>
        <string>lockdown</string>
    </array>
    <key>WatchPaths</key>
    <array>
        <string>${GSA_BASE_DIR}</string>
    </array>
    <key>StartInterval</key>
    <integer>300</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>StandardOutPath</key>
    <string>${GUARDIAN_LOG}</string>
    <key>StandardErrorPath</key>
    <string>${GUARDIAN_LOG}</string>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
PLIST
    /usr/sbin/chown root:wheel "${GUARDIAN_PLIST_PATH}"
    /bin/chmod 0644 "${GUARDIAN_PLIST_PATH}"

    # Bootstrap (idempotent: bootout first if already loaded).
    /bin/launchctl bootout "system/${GUARDIAN_PLIST_LABEL}" 2>/dev/null || true
    if /bin/launchctl bootstrap system "${GUARDIAN_PLIST_PATH}"; then
        log_info "Guardian LaunchDaemon installed and loaded."
    else
        log_error "Guardian bootstrap failed."
        return 1
    fi
}

remove_guardian() {
    if /bin/launchctl print "system/${GUARDIAN_PLIST_LABEL}" >/dev/null 2>&1; then
        /bin/launchctl bootout "system/${GUARDIAN_PLIST_LABEL}" 2>/dev/null || \
            log_warn "Guardian bootout returned non-zero (may already be gone)."
    fi
    /bin/rm -f "${GUARDIAN_PLIST_PATH}"
    log_info "Guardian LaunchDaemon removed."
}

# ---- Top-level actions -----------------------------------------------------

action_lockdown() {
    require_root
    require_macos

    if killswitch_active; then
        log_warn "Kill-switch is ACTIVE (${GSA_KILLSWITCH_FILE}). Lockdown invocation is honored, but the guardian will skip future re-assertion until the kill-switch file is removed."
    fi

    write_backup_snapshot "lockdown"

    local rc=0
    for p in "${GSA_LOCKDOWN_PATHS[@]}"; do
        apply_lockdown_path "${p}" || rc=1
    done

    install_guardian || rc=1

    log_info "Lockdown action complete (rc=${rc})."
    [ ${VERBOSE} -eq 1 ] && action_query
    return ${rc}
}

action_reset() {
    require_root
    require_macos

    write_backup_snapshot "reset"

    remove_guardian || true
    for p in "${GSA_LOCKDOWN_PATHS[@]}"; do
        reset_path "${p}"
    done

    log_info "Reset action complete. GSA is now upgrade-ready."
    [ ${VERBOSE} -eq 1 ] && action_query
}

# ---- Main ------------------------------------------------------------------

main() {
    parse_args "$@"
    case "${ACTION}" in
        query)    action_query ;;
        lockdown) action_lockdown ;;
        reset)   action_reset ;;
        *)        usage; exit 64 ;;
    esac
}

main "$@"
