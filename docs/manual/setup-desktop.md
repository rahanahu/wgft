# Windows and macOS agents

Issue a secret [join string with the procedure for your VPS](setup-alternatives.md#issue-a-join-string) and use it on the agent machine.
It can be used once and expires after one hour.

## Run the agent on Windows

Windows amd64 has been verified on Windows 11.
Download `wgft-windows-amd64.exe` and its `.sha256` file from [Releases](https://github.com/rahanahu/wgft/releases), then open PowerShell in that folder:

```powershell
if ((Get-FileHash -Algorithm SHA256 .\wgft-windows-amd64.exe).Hash -ne (Get-Content .\wgft-windows-amd64.exe.sha256).Split(' ')[0]) {
    throw "SHA256 mismatch"
}
Rename-Item wgft-windows-amd64.exe wgft.exe
$env:WGFT_JOIN = '<join string>'
.\wgft.exe agent run
```

Replace `<join string>` with the issued value.
Windows Defender Firewall may ask for inbound access on the first start. On the verified Windows 11 machine, the outbound tunnel and forwarding worked whether the prompt was allowed or cancelled.
Credentials are stored in `%ProgramData%\wgft\agent.json`; later starts need only `.\wgft.exe agent run`.
wgft does not include a Windows service or automatic startup.
The binary is unsigned.
On the machine used for verification, starting it from PowerShell did not show a SmartScreen warning, but an organization policy may prevent execution.

## Run the agent on macOS

Apple silicon (arm64) was verified on macOS 27.
Intel Macs are not supported.
Download and register once from Terminal:

```sh
curl -LO https://github.com/rahanahu/wgft/releases/latest/download/wgft-darwin-arm64
curl -LO https://github.com/rahanahu/wgft/releases/latest/download/wgft-darwin-arm64.sha256
shasum -a 256 -c wgft-darwin-arm64.sha256
sudo mkdir -p /usr/local/bin
sudo install -m 0755 wgft-darwin-arm64 /usr/local/bin/wgft
WGFT_JOIN='<join string>' /usr/local/bin/wgft agent run
```

Successful registration creates `~/Library/Application Support/wgft/agent.json`.
For a persistent service, stop the foreground agent with Ctrl+C and get the LaunchDaemon from the same release.
These commands replace `YOUR_USER`:

```sh
curl -fLO "https://raw.githubusercontent.com/rahanahu/wgft/$(wgft version | head -n 1)/deploy/io.github.rahanahu.wgft.agent.plist"
sed -e "s|/Users/YOUR_USER|$HOME|g" -e "s|YOUR_USER|$(id -un)|g" io.github.rahanahu.wgft.agent.plist > wgft-agent.plist
plutil -lint wgft-agent.plist
sudo install -m 0644 -o root -g wheel wgft-agent.plist /Library/LaunchDaemons/io.github.rahanahu.wgft.agent.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/io.github.rahanahu.wgft.agent.plist
```

The plist is readable by all users, so register from Terminal first and do not put the join string in it.
Check the service and log with:

```sh
sudo launchctl print system/io.github.rahanahu.wgft.agent | grep -E 'state|pid'
tail -f ~/Library/Logs/wgft-agent.log
```

Use `sudo launchctl bootout system/io.github.rahanahu.wgft.agent` to stop it.
The retained plist starts it again at the next boot.
On a Mac with FileVault enabled, it started after the first login.
Startup before login and operation after logout have not been verified.
This setup follows an observed failure to reach LAN targets from a LaunchAgent.

[日本語](setup-desktop.ja.md)
