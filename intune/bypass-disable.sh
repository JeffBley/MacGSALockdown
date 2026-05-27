#!/bin/bash
# intune/bypass-disable.sh
#
# Intune Shell Script payload (run as root, no user context).
# Clears BYPASS mode:
#   * removes the killswitch flag
#   * re-applies schg + deny ACEs on GSA paths
#   * reinstalls / reloads the guardian LaunchDaemon
#
# Deploy in Intune as a one-shot script after the user / admin has finished
# whatever required the bypass (upgrade, troubleshooting, etc.).

set -u

TOOL="/usr/local/libexec/macgsa-lockdown/macgsa-lockdown.sh"

if [ ! -x "${TOOL}" ]; then
    echo "macgsa-lockdown is not installed at ${TOOL}." >&2
    exit 2
fi

exec "${TOOL}" bypass off
