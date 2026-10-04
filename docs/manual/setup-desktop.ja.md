# Windows と macOS のエージェント

VPS の[起動方法に合う手順](setup-alternatives.ja.md#接続文字列の発行)で接続文字列を発行し、取得した秘密の join string を使います。
接続文字列は 1 回だけ使用でき、1 時間で期限切れになります。

## Windows で agent を実行する

Windows amd64 は Windows 11 で実機確認済みです。
[Releases](https://github.com/rahanahu/wgft/releases) から `wgft-windows-amd64.exe` と `.sha256` ファイルを取得し、そのフォルダで PowerShell を開きます。

```powershell
if ((Get-FileHash -Algorithm SHA256 .\wgft-windows-amd64.exe).Hash -ne (Get-Content .\wgft-windows-amd64.exe.sha256).Split(' ')[0]) {
    throw "SHA256 mismatch"
}
Rename-Item wgft-windows-amd64.exe wgft.exe
$env:WGFT_JOIN = '<join string>'
.\wgft.exe agent run
```

`<join string>` を発行した値に置き換えます。
初回起動時に Windows Defender Firewall が受信の許可を求めることがあります。Windows 11 の実機では、許可してもキャンセルしても外向きのトンネルと転送は動作しました。
認証情報は `%ProgramData%\wgft\agent.json` に保存され、次回は `.\wgft.exe agent run` だけで起動できます。
Windows のサービスや自動起動の機能は同梱していません。
バイナリはコード署名されていません。
実機では PowerShell からの起動で SmartScreen の警告は出ませんでしたが、組織のポリシーによって実行できない場合があります。

## macOS で agent を実行する

Apple シリコン (arm64) の macOS 27 で実機確認済みです。
Intel Mac には対応していません。
ターミナルでバイナリを取得し、1 回だけ登録します。

```sh
curl -LO https://github.com/rahanahu/wgft/releases/latest/download/wgft-darwin-arm64
curl -LO https://github.com/rahanahu/wgft/releases/latest/download/wgft-darwin-arm64.sha256
shasum -a 256 -c wgft-darwin-arm64.sha256
sudo mkdir -p /usr/local/bin
sudo install -m 0755 wgft-darwin-arm64 /usr/local/bin/wgft
WGFT_JOIN='<join string>' /usr/local/bin/wgft agent run
```

登録に成功すると `~/Library/Application Support/wgft/agent.json` が作られます。
常駐させる場合は、Ctrl+C で agent を止めてから、同じリリースの LaunchDaemon を取得します。
`YOUR_USER` は次のコマンドで置き換えます。

```sh
curl -fLO "https://raw.githubusercontent.com/rahanahu/wgft/$(wgft version | head -n 1)/deploy/io.github.rahanahu.wgft.agent.plist"
sed -e "s|/Users/YOUR_USER|$HOME|g" -e "s|YOUR_USER|$(id -un)|g" io.github.rahanahu.wgft.agent.plist > wgft-agent.plist
plutil -lint wgft-agent.plist
sudo install -m 0644 -o root -g wheel wgft-agent.plist /Library/LaunchDaemons/io.github.rahanahu.wgft.agent.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/io.github.rahanahu.wgft.agent.plist
```

plist は全利用者が読めるため、join string を書かずに、最初の登録をターミナルで済ませます。
動作とログは次で確認します。

```sh
sudo launchctl print system/io.github.rahanahu.wgft.agent | grep -E 'state|pid'
tail -f ~/Library/Logs/wgft-agent.log
```

停止には `sudo launchctl bootout system/io.github.rahanahu.wgft.agent` を使います。
plist が残っていると次回の起動時には再び起動します。
FileVault を有効にした実機では、最初のログイン後に起動しました。
ログイン前の起動やログアウト後の稼働は未確認です。
この構成は、LaunchAgent で LAN 内の接続に失敗した実測を踏まえています。

[English](setup-desktop.md)
