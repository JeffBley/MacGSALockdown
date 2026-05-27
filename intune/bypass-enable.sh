#!/bin/bash
# intune/bypass-enable.sh
#
# Intune Shell Script payload (run as root, no user context).
# Puts macgsa-lockdown into BYPASS mode:
#   * drops the killswitch flag at
#     /Library/Application Support/Microsoft/GSA-Lockdown/IsAntiTamperingDisabled
#   * unlocks /Applications/GlobalSecureAccessClient and children
#   * leaves the guardian LaunchDaemon loaded so 'bypass off' can re-assert
#
# Deploy in Intune as a one-shot script (not recurring). To re-lock, deploy
# intune/bypass-disable.sh.

set -u

TOOL="/usr/local/libexec/macgsa-lockdown/macgsa-lockdown.sh"

if [ ! -x "${TOOL}" ]; then
    echo "macgsa-lockdown is not installed at ${TOOL}." >&2
    exit 2
fi

exec "${TOOL}" bypass on
