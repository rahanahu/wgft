# Update an existing installation

English | [日本語](upgrade.ja.md)

Keep the server's data directory and the agent's credentials when replacing wgft.
An update does not require another join string while the registered agent's `agent.json` remains in its data directory.
Read the target release's [release notes](https://github.com/rahanahu/wgft/releases) before installing it.

## Data and configuration to preserve

| Installation | Persistent data | Configuration |
| --- | --- | --- |
| Linux systemd server | `/var/lib/wgft`, backed by `/var/lib/private/wgft` with the supplied `DynamicUser` unit | `/etc/wgft/server.env`, installed unit and any local drop-ins |
| Linux systemd agent | `/var/lib/wgft/agent.json` and its data directory | `/etc/wgft/agent.env`, installed unit and any kernel-mode drop-in |
| Foreground Linux agent from the README | `~/.wgft` | The flags and environment used to start it |
| Windows agent | `%ProgramData%\wgft\agent.json` | The startup account, flags and environment |
| macOS agent from the desktop guide | `~/Library/Application Support/wgft` | The LaunchDaemon plist and any startup settings |
| Docker | The named volumes mounted at `/var/lib/wgft` | Edited compose files |

For a custom `WGFT_DATA_DIR` or `--data-dir`, preserve that directory instead.
The server database contains keys and certificates, and agent credentials contain secrets.
Keep backups private and retain their ownership and permissions.

Back up the server's whole data directory before updating, along with configuration and the agent's data directory.
For a filesystem copy of the SQLite database, stop the server so the database and any WAL files are not changing during the copy.
Stop the agent before copying its credentials for the same reason.
Confirm that the backup exists and that you can read it before replacing the binary.
Resume the existing services after the backup so the binary-only sequence below starts with both sides running.
The supplied server unit's data-directory symlink means that a backup must include the directory contents, not only the symlink.

## Linux binary and systemd update

This procedure assumes the [Linux setup](setup.md), preserves the installed service units, and keeps each side's existing mode and configuration.
Download the binary and checksum with the setup guide's [installation commands](setup.md#1-install-the-binary); choose the target release rather than `latest` when installing a specific version.
Use `amd64` or `arm64` for the host architecture.
Do not repeat registration or user creation.

After the backup, replace the server binary on the VPS and restart its service:

```sh
sudo install -m 0755 wgft-linux-amd64 /usr/local/bin/wgft
sudo systemctl restart wgft
sudo wgft server check
sudo wgft agent ls
sudo wgft rule ls
```

Check the startup log and confirm that the existing agent reconnects before updating the home side.
Then replace the agent binary on the home Linux machine:

```sh
sudo install -m 0755 wgft-linux-amd64 /usr/local/bin/wgft
sudo systemctl restart wgft-agent
sudo runuser -u wgft -- wgft agent doctor
```

Check the rule with the real service client from outside the VPS.
Use [troubleshooting](troubleshooting.md) if startup or forwarding does not recover.
Userspace forwarding stops with its process.
Kernel forwarding can remain while the process restarts, but an update does not guarantee uninterrupted existing sessions or a fixed recovery time.

If release notes require an updated unit, use the unit installation and `daemon-reload` steps from the setup guide and preserve local settings.
The binary-only steps above do not replace the unit or a kernel-mode drop-in.
Changing mode is a separate operation; a kernel agent must follow [the mode-change procedure](agent-kernel.md#return-to-userspace-mode).

## Desktop and container installations

On Windows, stop the foreground agent, verify the replacement binary's checksum as in [desktop setup](setup-desktop.md#run-the-agent-on-windows), replace the executable, then run it again as the same user.
Keep `%ProgramData%\wgft\agent.json`; no new join string is needed.

On macOS, use the [desktop setup](setup-desktop.md#run-the-agent-on-macos) to verify and install the replacement binary.
For the supplied LaunchDaemon, stop it with the documented `launchctl bootout` command before replacement and start it with the documented `launchctl bootstrap` command afterward.
Preserve the credentials directory and the configured `UserName`.
This update path combines the published installation and stop/start procedures; an upgrade with the LaunchDaemon has not been separately verified.

For Docker, preserve both named state volumes when replacing or recreating containers and review the image version and compose changes for the target release.
`docker compose ... down -v` removes volumes and belongs to removal, not an update.
The [Docker guide](setup-docker.md) describes the persistent mounts and starting the containers; it does not provide a separately verified image-update recipe.

## Downgrade limits

Downgrading after an update is not guaranteed.
The server database uses schema version 9 from v1.2.0 onward; v1.1.x and earlier servers cannot open it.
Replacing only the binary with an older version does not undo a database migration.
Keep the pre-update backup and the old release binary for recovery planning; no automatic downgrade or restore command is provided.

Before returning a kernel-mode agent to v1.1.x, run `agent teardown` with a v1.2 or newer binary, following the [kernel agent guide](agent-kernel.md#return-to-userspace-mode).
Teardown keeps registration and keys; server teardown with `--purge` removes them and is not an update step.
The supported compatibility surfaces and exclusions are defined in [the compatibility contract](../design/compatibility.md#7a11-v10-の互換性の保証サーフェスごとの一覧).

[User manuals](README.md) · [Troubleshooting](troubleshooting.md)
