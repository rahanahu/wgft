package store

// サーバのデータベースの meta 表のキー。値はデータベースに保存されるので、文字列を変えると既存の
// データベースの記録を読めなくなる。キーを使う package がどこにあっても、ここで名前を付ける。
const (
	// MetaGeneration はルール集合の世代。
	MetaGeneration = "generation"
	// MetaServerKey は WireGuard のサーバの秘密鍵。
	MetaServerKey = "wg_server_private_key"
	// MetaMode は記録済みの転送方式(仕様 9・11a 節)。値は ModeKernel か ModeUserspace。
	MetaMode = "mode"
	// MetaWGAddress は記録済みの wg のアドレス帯(仕様 11a 節)。
	MetaWGAddress = "wg_address"

	// 撤去のために vpsd が起動時に残す記録。teardown が --state だけで手掛かりを得られる。

	// MetaTeardownWGInterface は wg インタフェースの名前。
	MetaTeardownWGInterface = "teardown_wg_interface"
	// MetaTeardownWGPort は WireGuard の UDP のポート。
	MetaTeardownWGPort = "teardown_wg_port"
	// MetaTeardownAgentAPIPort はエージェント用 API の TCP のポート。
	MetaTeardownAgentAPIPort = "teardown_agent_api_port"
	// MetaIPForwardSetAt は、wgft が net.ipv4.ip_forward を 0 から 1 にした日時。書けた後に保存する
	// 確定の記録である(仕様 6.1 節)。
	MetaIPForwardSetAt = "ip_forward_set_by_wgft_at"
	// MetaIPForwardWriteStartedAt は、wgft が net.ipv4.ip_forward の値 0 を読み、1 を書き始めた日時。
	// 書く前に保存する予定の記録であり、書けたかどうかは述べない。確定の記録を保存するトランザクション
	// で消す(仕様 6.1 節)。
	MetaIPForwardWriteStartedAt = "ip_forward_write_started_by_wgft_at"

	// MetaAgentAPICert と MetaAgentAPIKey はエージェント用 API の自己署名の証明書と秘密鍵(PEM)。
	MetaAgentAPICert = "agent_api_cert_pem"
	MetaAgentAPIKey  = "agent_api_key_pem"
)

// MetaMode に記録する転送方式の値(仕様 9・11a 節)。
const (
	ModeKernel    = "kernel"
	ModeUserspace = "userspace"
)
