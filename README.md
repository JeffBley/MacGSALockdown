# MacGSALockdown

A macOS analog of the Windows [GSALockdown](https://github.com/idMdev/GSALockdown) tool. Hardens the Microsoft Entra **Global Secure Access (GSA) Client** on macOS so a local admin cannot casually disable, uninstall, or delete it.

> **Honest threat model.** macOS has no per-service ACL like Windows SCM, and the deepest tamper-resistance for a Network Extension is enforceable **only via MDM**. This project therefore ships two layers:
>
> 1. **Local lockdown** (`schg` + extended deny ACEs + a guardian LaunchDaemon) — stops drag-to-Trash, the bundled Uninstaller, and casual `sudo rm`. Reversible by a determined root user who runs `sudo chflags noschg` first.
> 2. **MDM Configuration Profile** (`profiles/GSA-Lockdown.mobileconfig`) — locks the System Extension as non-removable from System Settings. **This is the only way to block the "user toggles off the extension" path.**
>
> Deploy **both** layers via Intune for parity with the Windows tool's protection level.

## Repository layout

| Path | Purpose |
|---|---|
| `bin/macgsa-lockdown.sh` | Main script. Verbs `query` / `lockdown` / `reset` mirror the Windows tool. |
| `bin/lib-common.sh` | Shared helpers (logging, root check, state inspection, constants). |
| `launchd/com.contoso.gsaguardian.plist` | Reference copy of the guardian LaunchDaemon. The real plist is written by the installer with absolute paths. |
| `intune/install-lockdown.sh` | Intune shell script: stages files under `/usr/local/libexec/macgsa-lockdown/` and runs `lockdown`. |
| `intune/uninstall-lockdown.sh` | Intune shell script: runs `reset` and removes staged files. Use before upgrading GSA. |
| `profiles/GSA-Lockdown.mobileconfig` | MDM profile that pre-approves and locks down the GSA Network Extension. |

## How it maps to the Windows tool

| Windows GSALockdown | MacGSALockdown equivalent |
|---|---|
| `sc.exe sdset` per-service DACL | `chmod +a "everyone deny …"` on `/Applications/GlobalSecureAccessClient/*` |
| Registry SDDL hardening | `chflags -R schg` on the same paths |
| `$LockdownScmSddlMap` / `$DefaultScmSddlMap` | `factory-state.json` snapshot under `/Library/Application Support/Microsoft/GSA-Lockdown/` |
| JSON snapshot at `%TEMP%\lockdown-GSA-backup-…` | JSON snapshot at `/var/log/macgsa-lockdown-backup-…` |
| `Action Query` / `Lockdown` / `Reset` | Same verbs: `query` / `lockdown` / `reset` |
| `IsAntiTamperingDisabled` registry value (GSAWatcher) | Presence of `/Library/Application Support/Microsoft/GSA-Lockdown/IsAntiTamperingDisabled` |
| Runs as `SYSTEM` via Intune | Runs as `root` via Intune shell script |
| `unlock-gsa.ps1` SYSTEM-context Scheduled Task | `intune/uninstall-lockdown.sh` (root is the highest local principal on macOS) |
| Service-stop event-triggered watchdog (GSAWatcher) | Guardian LaunchDaemon with `WatchPaths` on `/Applications/GlobalSecureAccessClient/` + `StartInterval=300` belt-and-braces |

## Local testing (no Intune required)

```bash
# 1. Inspect current state (read-only, no changes).
sudo bin/macgsa-lockdown.sh query

# 2. Apply lockdown.
sudo bin/macgsa-lockdown.sh lockdown --verbose

# 3. Attempt to tamper as an admin — these should all FAIL:
sudo rm -rf "/Applications/GlobalSecureAccessClient/Global Secure Access Client.app"
open "/Applications/GlobalSecureAccessClient/Uninstall Global Secure Access Client.app"
# (Drag to Trash from Finder also fails.)

# 4. Re-inspect; everything should still show Overall=Lockdown.
sudo bin/macgsa-lockdown.sh query

# 5. Reset before any legitimate GSA upgrade.
sudo bin/macgsa-lockdown.sh reset --verbose

# 6. Run the GSA upgrade installer, then re-apply lockdown.
sudo bin/macgsa-lockdown.sh lockdown
```

### Break-glass: kill-switch

If you need the guardian to stop re-asserting state (e.g. troubleshooting), drop a marker file:

```bash
sudo mkdir -p "/Library/Application Support/Microsoft/GSA-Lockdown"
sudo touch     "/Library/Application Support/Microsoft/GSA-Lockdown/IsAntiTamperingDisabled"
```

Remove the file to re-arm. This mirrors the Windows `IsAntiTamperingDisabled` registry value used by GSAWatcher.

## Intune deployment

### A. Configuration profile (MDM-only protection)

1. Microsoft Intune admin center → **Devices → Configuration → Create → New policy → macOS → Templates → Custom**.
2. Upload `profiles/GSA-Lockdown.mobileconfig`. Edit the file first to:
   - Replace `Contoso` / `com.contoso.*` with your org identifiers.
   - Regenerate the three `PayloadUUID` values (`uuidgen`).
3. Assign to your macOS device group. Wait for sync.
4. Verify on a test Mac:
   ```bash
   profiles list -all | grep -i lockdown
   systemextensionsctl list        # GSA tunnel should show [activated enabled]
   ```
   In **System Settings → General → Login Items & Extensions → Network Extensions**, the GSA toggle should be greyed out.

### B. Lockdown shell script

1. Bundle into a single folder for upload:
   ```
   gsa-lockdown-bundle/
     install-lockdown.sh       (from intune/)
     macgsa-lockdown.sh        (copy of bin/macgsa-lockdown.sh)
     lib-common.sh             (copy of bin/lib-common.sh)
   ```
   The installer auto-detects the flat layout.
2. Intune admin center → **Devices → macOS → Shell scripts → Add**.
3. Upload `install-lockdown.sh`. Settings:
   - **Run script as signed-in user:** No
   - **Hide script notifications on devices:** Yes
   - **Script frequency:** Not configured (once) — or weekly for self-healing
   - **Max number of times to retry if script fails:** 3
4. Assign to the same macOS device group.

### Upgrading GSA via Intune

1. Temporarily assign `intune/uninstall-lockdown.sh` to the target group; wait for it to run.
2. Push the new GSA Client `.pkg` (Apps → macOS → Line-of-business app).
3. Re-assign `intune/install-lockdown.sh`.

## What's verified vs. what's not

| | |
|---|---|
| ✅ Discovered against a real install | App path, system ext bundle ID, team ID, pkg ID — all captured from a running Mac mini with GSA Client 1.1.25111702. |
| ⚠️ Untested on this checkout | The scripts target macOS-only syscalls (`chflags`, `launchctl bootstrap`, `chmod +a`) and cannot be run on the Windows machine where this repo was authored. Test on macOS 14+ before fleet rollout. |
| ⚠️ MDM profile syntax | Validated against current Apple documentation for `com.apple.system-extension-policy`. The optional `com.apple.vpn.managed` block is commented because GSA writes its own NE config at first launch — pushing a managed config in parallel can conflict. Enable only after testing on one device. |

## Limitations

- Defense-in-depth only. A determined root user can `sudo chflags noschg ...` to unwind the local lockdown, and (without the MDM profile) can toggle off the extension in System Settings. The MDM profile closes the System Settings path; nothing fully closes the `sudo` path short of MDM-managed app/profile removal restrictions on a supervised device.
- No code signing on the scripts. If you want notarized binaries, port `bin/` to a Swift command-line tool, sign with your Developer ID, and re-wrap. The bash version is intentionally chosen to keep Intune deployment trivial.
- The guardian uses `WatchPaths`, which fires on metadata changes inside the watched directory. macOS may coalesce rapid events; the 5-minute `StartInterval` poll covers the gap.
