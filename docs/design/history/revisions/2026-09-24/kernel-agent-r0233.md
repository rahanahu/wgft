<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 267 です。

# 2026-09-24: kernel-agent

- エージェントのカーネルモードの drop-in の例を配った(2026-09-24、所有者の決定を含む):7b.5 節の unit の項に、`deploy/agent.kernel.conf` の中身と置き場所を書いた。
  所有者の決定は、`agent.service` を変えず、`CAP_NET_ADMIN` を加える drop-in の例を配ること、drop-in に `ProtectKernelTunables=` を付けないこと、`RestrictAddressFamilies=` に `AF_NETLINK` を残すこと、Docker でのカーネルモードを v1.2 の手順に書かないことである。
  配布物の VM 試験(docs/development/testing.md の B9)に、この drop-in と `WGFT_MODE=kernel` でエージェントを入れる `--agent-kernel` を加え、Debian 12 の VM で次を確かめた。
  エージェントのプロセスが `wgft` の利用者で動き、実効、ambient、境界の権限の集合が `CAP_NET_ADMIN` だけであること。
  エージェントのホスト自身のアドレスへの TCP と UDP と、別のホストへの TCP が転送されること。
  VM の再起動の後に転送が戻ること。
  エージェントの停止中も転送が続くこと。
  `agent doctor` が、稼働中は root でも `wgft` の利用者でも終了コード 0 になり、停止中は root で 0、`wgft` の利用者で `needs_cap_net_admin` の 2 になること。
  drop-in を置かずに `WGFT_MODE=kernel` で起動すると、ログに `CAP_NET_ADMIN` を示して終了コード 3 で止まること。
  `wgft agent teardown` がインタフェースとテーブルを消し、`agent.json` の持ち主を保ち、その後にユーザー空間モードで転送できること。
  動いているユーザー空間モードのエージェントに drop-in と `WGFT_MODE=kernel` を加えて再起動すると、カーネルモードで転送できること。
  試験用の実機の Proxmox VE の非特権の LXC のコンテナ(Debian 13、nesting を有効、AppArmor のプロファイルは unconfined)でも、同じ drop-in で次を確かめた。
  権限の集合が `CAP_NET_ADMIN` だけであること。
  エージェントのサービスの再起動の後とコンテナ自体の再起動の後に転送が戻ること。
  エージェントを止めている間も転送が続くこと。
  稼働中と停止中の `rotate-key` が通ること。
  drop-in に `CapabilityBoundingSet=CAP_NET_ADMIN` の行が無いと、空の境界の集合のもとで ambient の集合も空になることは、Debian 12 のコンテナの `systemd-run` で確かめた。
  これにより 7b.7 節の「固定の `User=wgft` の unit に `CAP_NET_ADMIN` を重ねた配置」の項を外し、Debian 以外のディストリビューションでの確かめの項に改めた。
  7b.7 節の Proxmox のコンテナの項は、nesting が無効の場合と AppArmor のプロファイルが制限をかける場合に絞った。
  7a.11 節の `deploy/` の同梱物の保つものに、drop-in のファイル名を加えた。
  利用者が手順の中でパスで参照するためである。
  リリースのバイナリの `wgft version` の 1 行目がリリースのタグそのものであることを、7a.11 節のリリース成果物の項の保つものに加えた。
  docs/manual/setup.md の手順がこの行で unit のファイルをタグから取得するためであり、`.goreleaser.yaml` の `-X` の値とテスト `TestVersionSubcommand` が既にこの形を固定している
