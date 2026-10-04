# Windows と macOS のエージェント

Windows と macOS のエージェントの試験は、Linux のラボに含めません。
Linux のラボは Incus の VM、network namespace、Linux のカーネル、nftables、WireGuard で組んだ環境であり、Windows と macOS に固有の経路 (認証情報の ACL、UDP の待ち方、UDP の送信バッファ、launchd、スリープ、ネットワークの変化) を再現しないためです。
同じ理由で、Windows と macOS の試験をラボの一式 (A9) に含めません。

過去に実機で見つかった不具合と回帰テストへの置き換えは[確認の記録](history/testing-validation.md#実機の確認を小さな回帰テストに置き換えた範囲)にあります。

Windows と macOS の試験は、次のように類を分けます。

| 時点 | Windows | macOS |
|---|---|---|
| すべての PR (A 類) | クロスビルドと `go vet` (A7) | クロスビルドと `go vet` (A7) |
| 関係する PR (B 類) | Windows の runner での単体テスト (B4) | macOS の runner での単体テスト (B8) |
| 段階の完了 (C 類) | 含めない (C 類は Linux の VM と悪い条件のネットワークを扱う) | 含めない |
| リリース候補 (D 類) | エージェントの smoke (D1) | エージェントの smoke (D2) |
| 関係する変更の後の手作業 (E 類) | スリープと復帰、アダプタの無効と有効、Wi-Fi の再接続 (E4) | スリープと復帰、Wi-Fi とインタフェースの変化、再起動の後の launchd (E5) |

### Windows のエージェントの smoke の内容

D1 は、リリースのバイナリ (`wgft-windows-amd64.exe`) を、ラボか試験用の実 VPS の server に対して動かし、次の点を確かめます。

- 起動と登録:管理者の権限を持たない利用者が `agent run` を起動し、登録が通るかを確かめます
- TCP と UDP の転送:Windows 自身と LAN の他のホストへの転送が通るかを確かめます
- 大きな UDP:トンネルの MTU を超えるデータグラム (3000 バイトと 12000 バイト) が欠けずに届くかを確かめます
- 再接続:server の再起動と、エージェントの再起動の後に転送が戻るかを確かめます
- UDP の受信の固着:server の UDP のポートが一時的に届かなくなった後、送信は続くのに受信だけが止まったままにならないか、エージェントを再起動せずに戻るかを確かめます
- 状態の保持:保存した認証情報で、登録をやり直さずに起動できるかを確かめます。
  認証情報のファイルの ACL が保護されたままであることも確かめます
- ネットワークアダプタの無効と有効:アダプタを無効にして有効に戻した後に、転送が戻るかを確かめます
- リリースのバイナリ:ビルドし直した物ではなく Releases の物が、Windows Defender ファイアウォールの確認 (許可と取り消しのどちらでも) の後に動くかを確かめます

環境の候補は、Linux のホストの上の Windows の VM、Windows の CI の runner、Windows の実機の 3 つです。
Windows の VM は、Linux のラボの netns の中には入らず、別の VM としてラボの server に接続します。
Windows の VM で D1 のどこまでを再現できるかは未確認です。
Windows の CI の runner で登録と転送を確かめるには、runner から届く server を CI から用意する仕組みが要るので、現在は使いません。
VM のスリープが実機のスリープと同じ経路 (ネットワークのドライバの停止と再開) を通るかは未確認なので、スリープと復帰は実機で確かめます (E4)。
無人での常駐 (サービスや SYSTEM としての実行) は未確認で、確認の対象に含めません。

Windows の実機の代わりに、同じ Windows 機の WSL2 に server を置き、`networkingMode=mirrored` で client と結ぶ構成もあります。
この構成は登録、ルールの扱い、認証情報の保存、D1 で使う CLI の確認には十分ですが、client と server が別のホストにある本来の構成の経路を再現しません。
次の 3 点は、この構成だけで判定すると誤ります (issue #87)。

| 効果 | 内容 |
|---|---|
| 経路の再現 | mirrored networking では WSL2 の guest が Windows host のアドレスを共有するため、待ち受けの無いポート宛てのデータグラムは guest に届かず、Windows host 自身が ICMP を返します。実 VPS を実回線越しに使う確認では、同じ種の送信でも WinRingBind に WSAECONNRESET は現れませんでした。VPS が ICMP を生成したか、経路上で失われたかは切り分けていません |
| MTU の頭打ち | mirrored の経路は wgft と無関係な UDP の制御用の応答でも頭打ちになるため、3000 バイトと 12000 バイトの確認は判定できません。1420 バイトのトンネルの MTU を上回る転送そのものは、この経路でも成功しました |
| アダプタの無効と有効 | Windows host のアダプタを無効にして有効に戻しても、mirrored networking の guest は自分のネットワークインタフェースを失ったままでした。server がその guest にあると、client の経路の消失と server の消失が同時に起き、アダプタの項目を切り分けられません |

D1 の「UDP の受信の固着」「大きな UDP」「ネットワークアダプタの無効と有効」を確かめるには、client と server が別のホストにある構成が要ります。
WSL2 の mirrored networking は、それ以外の D1 の確認には有効な近道です。

### macOS のエージェントの smoke の内容

D2 は、リリースのバイナリ (`wgft-darwin-arm64`) を Apple シリコンの Mac の実機で動かし、次の点を確かめます。

- リリースのバイナリ:README の手順 (`curl` での取得と sha256 の照合) で導入したバイナリが、Gatekeeper に止められずに動くかを確かめます
- launchd:同梱の `deploy/io.github.rahanahu.wgft.agent.plist` で LaunchDaemon として起動し、強制終了の後に再起動されるかを確かめます
- TCP と UDP の転送:Mac 自身と LAN の他のホストへの転送が通るかを確かめます
- 大きな UDP:9216 バイトを超えるデータグラム (12000 バイト) が宛先に届くかを確かめます
- 再接続:server の再起動と Mac の再起動の後に、転送が戻るかを確かめます

macOS の挙動は Linux の上で再現できるとはみなしません。
macOS の CI の runner は単体テスト (B8、CI の `macos-test`) には使えますが、launchd、スリープと復帰、ネットワークの変化の確認は、実機での手作業の関門 (D2 と E5) にします。
runner の macOS が実機と同じ UDP の送信バッファの既定 (9216 バイト) を持つかは未確認です。
FileVault を無効にした Mac でのログイン無しの起動と、ログアウトの後の動作は未確認です。


検査の契機と頻度は[テストの規範](testing.md)、過去の回帰テストへの置き換えは[確認の記録](history/testing-validation.md#実機の確認を小さな回帰テストに置き換えた範囲)にあります。
