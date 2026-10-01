package controlapi

import (
	"time"

	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

// 稼働中のエージェントの診断(設計文書 10.2c 節)。制御ソケットの doctor が返す 1 行の JSON は、
// 稼働中のプロセスしか持たない証拠だけを載せる。認証情報ファイル、OS、名前解決のような静的で
// 永続する事実は、エージェントが止まっていても読めるので CLI 自身が読み、この応答には入れない。
//
// 運用者が読む wgft agent doctor --json の出力とこの応答は別の模型であり、この応答はその材料である。
// どの検査にどう畳むか、どの状態の語を当てるか、終了コードをどう決めるかは CLI が決める。

// DoctorCommand は制御ソケットに送る 1 行の要求である。
const DoctorCommand = "doctor"

// DoctorResponse は doctor の応答である。1 行の JSON として送る。
//
// Error があるときは、他の 3 つの項目が無い。応答を組む処理が panic したことを表すためである。
// RuntimeState が無く RuntimeStateTimeout があるときは、実行時の状態を守る排他を期限内に
// 取れなかったことを表す。エージェントは生きているが内部の処理で詰まっている。
type DoctorResponse struct {
	// Error は応答を組む処理が失敗したことと、その理由である。運用者に何が起きたかを伝えるために
	// 載せる。値があるとき、残りの項目は無い
	Error string `json:"error,omitempty"`

	// AllowTargets は宛先の許可一覧である。起動時に決まって以後変わらず、実行時の排他も要らないので、
	// 排他を取れなかった応答にも載る
	AllowTargets *DoctorAllowTargets `json:"allow_targets,omitempty"`

	// Stream は制御ストリームの観測である。internal/agent の streamMu だけで読めるので、実行時の
	// 排他を取れなかった応答にも載る
	Stream *DoctorStream `json:"stream,omitempty"`

	// Process は稼働中のエージェントのプロセスの実行主体である。実行時の排他を要らないので、排他を
	// 取れなかった応答にも載る(設計文書 10.2c 節の「カーネルモードの制御ソケットの応答」)
	Process *DoctorProcess `json:"process,omitempty"`

	// RuntimeState は実行時の排他の下でしか読めない状態である。排他を期限内に取れなければ無い
	RuntimeState *DoctorRuntimeState `json:"runtime_state,omitempty"`
	// RuntimeStateTimeout は、実行時の排他を取れなかったときに待った期限である。単位はナノ秒。
	// 取れた場合は 0 になる
	RuntimeStateTimeout time.Duration `json:"runtime_state_timeout,omitempty"`
}

// DoctorAllowTargets は宛先の許可一覧である。一覧の中身はエージェントのホストにしか無く、
// server には届かない(設計文書 10.2c 節)。
type DoctorAllowTargets struct {
	// Set は一覧を持っているかどうか。偽なら、server はこのエージェントが届くどの宛先も指せる
	Set bool `json:"set"`
	// List は正規化した一覧。Set が偽なら空
	List string `json:"list,omitempty"`
	// Env は一覧を渡す設定の名前
	Env string `json:"env"`
}

// DoctorProcess は稼働中のエージェントのプロセスの実行主体である。root で実行した agent doctor は
// ファイルのパーミッションを迂回するので、エージェント自身がどの利用者で動いているかを添える
// (設計文書 10.2c 節)。
type DoctorProcess struct {
	// UID は実 uid である。Windows では -1 になる
	UID int `json:"uid"`
	// User は UID の利用者名である。引けなければ空になる。systemd の DynamicUser の利用者は
	// /etc/passwd に無いので、静的なビルドでは引けないことがある
	User string `json:"user,omitempty"`
	// NetAdmin は、プロセスが実効として CAP_NET_ADMIN を持つかどうかである。Linux の外と、読めな
	// かった場合は nil になる
	NetAdmin *bool `json:"cap_net_admin,omitempty"`
}

// DoctorStream は制御ストリームの観測の写しである。項目の意味は internal/agent の
// streamObservation にある。
type DoctorStream struct {
	Connected bool `json:"connected"`
	// DisconnectedAt と RetryAt、LastPingAt、LastPongAt は、値が無ければゼロ値の時刻になる。
	// encoding/json の omitempty は struct に効かないので、項目そのものは必ず出る。読み手は
	// IsZero で判定する
	DisconnectedAt   time.Time `json:"disconnected_at"`
	DisconnectReason string    `json:"disconnect_reason,omitempty"`
	// PinMismatch は、直近の切断か試みの失敗が、server の証明書と登録のときに固定したハッシュとの
	// 不一致だったことである。旧い版のエージェントは送らない
	PinMismatch bool `json:"pin_mismatch,omitempty"`
	// Backoff は直近に待った再接続の間隔。単位はナノ秒
	Backoff      time.Duration `json:"backoff,omitempty"`
	RetryAt      time.Time     `json:"retry_at"`
	LastPingAt   time.Time     `json:"last_ping_at"`
	LastPongAt   time.Time     `json:"last_pong_at"`
	AwaitingPong bool          `json:"awaiting_pong"`
}

// DoctorRuntimeState は実行時の排他の下で 1 度に読んだ状態である。トンネル、ルール、フロー予算の
// 値はどれも同じ時点のものである。
type DoctorRuntimeState struct {
	// Mode は稼働中のエージェントの転送の方式である(kernel か userspace。仕様 11a 節)。旧い版の
	// エージェントは送らないので、空ならユーザー空間モードである
	Mode string `json:"mode,omitempty"`
	// Generation は最後に受け取って処理した全体状態の世代
	Generation uint64       `json:"generation"`
	Tunnel     DoctorTunnel `json:"tunnel"`
	// Rules はルールごとの状態である。リスナー 1 つずつは並べない。ルールを受け付ける資源が無ければ
	// 項目ごと出ない。カーネルモードでは、リスナーの数と中継の数はどれも 0 で、状態と理由だけが意味を持つ
	Rules []DoctorRule `json:"rules,omitempty"`
	// Budgets はプロトコルごとのフロー予算である。中継が無ければ項目ごと出ない
	Budgets []DoctorBudget `json:"budgets,omitempty"`
	// RefusalsSince は Budgets の拒否の累計の起点、つまり今のトンネルを立てた時刻である。
	// フロー予算はトンネルを立て直すたびに中継ごと作り直され、累計はそのたびに 0 に戻る
	// (設計文書 10.2c 節)。中継が無ければゼロ値の時刻になる。項目そのものは必ず出るので、
	// 読み手は IsZero で判定する
	RefusalsSince time.Time `json:"refusals_since"`
	// AgentDisabled は、最後に適用した全体状態の proto.State.AgentDisabled をそのまま写した
	// ものである(仕様 5.1 節)。server がこのエージェントを無効にしていることをエージェント
	// 自身の診断のために示すだけで、守りには使わない。relay.listeners はこの値から SKIPPED を
	// 判定する(設計文書 10.2c 節)
	AgentDisabled bool `json:"agent_disabled"`

	// Kernel はカーネルモードの dataplane を読んだ結果である(設計文書 10.2c 節)。カーネルモードの
	// エージェントだけが持つ。停止中の agent doctor も internal/agent の ReadKernel で同じ形を読む
	Kernel *DoctorKernel `json:"kernel,omitempty"`
	// PublishError は、公開できずに試し直している全体状態の誤りである(7b.3 節の 3 つ目の種類)。
	// 旧いテーブルが残って転送を続けている
	PublishError string `json:"publish_error,omitempty"`
	// CheckError は、カーネルモードの直前の見直しの誤りである。30 秒ごとの見直しと変更の通知の後の
	// 見直しの両方を指す(7b.4 節)
	CheckError string `json:"check_error,omitempty"`
}

// DoctorTunnel はトンネルの状態である。State と Reason はハートビートが組み立てる値そのもので、
// doctor のための 2 つ目の判定は持たない(設計文書 10.2c 節)。
type DoctorTunnel struct {
	// Present はトンネルがあるかどうか。偽なら Reason がその理由を言う
	Present bool `json:"present"`
	// State は ok か error
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
	// Endpoint は解決済みのエンドポイント。初回の名前解決に失敗したトンネルは持たない
	Endpoint string `json:"endpoint,omitempty"`
	// LastHandshake は今の device から読んだ最終ハンドシェイクである。watchdog が別に持つ値は
	// トンネルを閉じても消えず、立て直した直後は前のトンネルの値が残るので、そちらは載せない。
	// 成立していなければゼロ値の時刻になる。項目そのものは必ず出るので、読み手は IsZero で判定する
	LastHandshake time.Time `json:"last_handshake"`
	RxBytes       int64     `json:"rx_bytes"`
	TxBytes       int64     `json:"tx_bytes"`
	// StartedAt は今のトンネルを立てた時刻。トンネルが無ければゼロ値の時刻になる
	StartedAt time.Time      `json:"started_at"`
	Watchdog  DoctorWatchdog `json:"watchdog"`
	// SocketBuffers は、今のトンネルを立てた直後に測った WireGuard の UDP ソケットのバッファで
	// ある(設計文書 7 節と 10.2c 節)。ユーザー空間モードのトンネルがあるときだけ載る。旧い版の
	// エージェントは送らない
	SocketBuffers *DoctorSocketBuffers `json:"socket_buffers,omitempty"`
	// UDPAccounting は netstack の UDP の受信の会計の状態である(設計文書 7 節と 10.2c 節)。
	// ユーザー空間モードのトンネルがあるときだけ載る。旧い版のエージェントは送らない
	UDPAccounting *DoctorUDPAccounting `json:"udp_accounting,omitempty"`
}

// DoctorUDPAccounting は UDP の受信の会計の状態である。
type DoctorUDPAccounting struct {
	// Stopped は、会計が不変条件の違反を検出して、トンネルの UDP を止めたかどうかである
	Stopped bool `json:"stopped"`
	// Error は検出した違反である。Stopped のときだけ載る
	Error string `json:"error,omitempty"`
}

// DoctorSocketBuffers は WireGuard の UDP ソケットのバッファを測った結果である。値は
// internal/dataplane/userspace/sockbuf の Reading をそのまま写す。
type DoctorSocketBuffers struct {
	// Supported は、エージェントの OS で測る手段を持つかどうかである。Linux だけが真である。
	// 偽のとき、他の項目は無い
	Supported bool `json:"supported"`
	// Port は測った WireGuard の listen port である
	Port uint16 `json:"port,omitempty"`
	// Sockets はその port に bind した UDP ソケットのうち測れたものの数である
	Sockets int `json:"sockets,omitempty"`
	// Recv と Send は、測ったソケットのうち最も小さい実効の受信と送信のバッファである。単位はバイト
	Recv int `json:"recv,omitempty"`
	Send int `json:"send,omitempty"`
	// Required は条件の値である。単位はバイト。受信と送信のどちらにも同じ値を求める
	Required int `json:"required,omitempty"`
	// Error は測れなかった理由である
	Error string `json:"error,omitempty"`
}

// DoctorWatchdog はトンネルを作り直す判定の状態である。次の作り直しまでの残り時間は載せない。
// 残りは保持されておらず、示すには起点を求める規則を診断の側に写すことになるためである
// (設計文書 10.2c 節)。
type DoctorWatchdog struct {
	// RebuildInterval は判定に使う作り直しの間隔の実効値である。単位はナノ秒
	RebuildInterval time.Duration `json:"rebuild_interval"`
	// RetryAt は、作成に失敗して試し直しを待っている場合の予定の時刻。待っていなければゼロ値の
	// 時刻になる。項目そのものは必ず出るので、読み手は IsZero で判定する
	RetryAt time.Time `json:"retry_at"`
}

// DoctorRule はルール 1 本の状態である。リスナー 1 つずつは並べない。ポート範囲の幅に上限が無く、
// listen_port=1-65535 のルール 1 本で 65535 個のリスナーができるので、そのまま並べると 1 行が
// 数 MB になる(設計文書 10.2c 節)。
type DoctorRule struct {
	ID string `json:"id"`
	// State と Reason はハートビートが組み立てる proto.RuleStatus の値そのものである
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
	// Proto は tcp か udp
	Proto proto.Proto `json:"proto,omitempty"`
	// Listeners はこのルールに属するリスナーの数、Listening はそのうち待ち受けを開けている数である
	Listeners int `json:"listeners"`
	Listening int `json:"listening"`
	// BindErrors は待ち受けを開けなかったリスナーの数、BindError はその 1 つの理由である。
	// 開けない原因はポートの衝突を指す
	BindErrors int    `json:"bind_errors"`
	BindError  string `json:"bind_error,omitempty"`
	// TargetErrors は待ち受けは開いていて宛先に届かないリスナーの数、TargetError はその 1 つの
	// 理由である。届かない原因は宛先の機器を指すので、運用者の次の行動が bind の失敗とは違う
	TargetErrors int    `json:"target_errors"`
	TargetError  string `json:"target_error,omitempty"`
	// Sessions は中継が持っている接続の数である。TCP は公開側と宛先側の両方を数えるので、
	// フロー予算の上限の対象とは一致しない。上限の対象の数は Flows である
	Sessions int `json:"sessions"`
	Flows    int `json:"flows"`
	// Ports はルールの宣言のポートの数、DNATPorts はそのうちカーネルモードで DNAT を置いたポートの
	// 数である。カーネルモードのルールだけが持つ。DNAT を置いたまま error を報告するルールと、DNAT を
	// 持たないルールを見分けるためである(設計文書 10.2c 節)
	Ports     int `json:"ports,omitempty"`
	DNATPorts int `json:"dnat_ports,omitempty"`
}

// DoctorBudget は 1 つのプロトコルのフロー予算である。記号は設計文書 7a.10 節に合わせる。
type DoctorBudget struct {
	Proto proto.Proto `json:"proto"`
	// Total は予算 T、InUse は今のフロー数 u である
	Total int `json:"total"`
	InUse int `json:"in_use"`
	// RuleCap はルールが 2 本以上あるときのルール 1 本の上限 C、Reserve はルールの登録ごとの
	// 最低分 m、Rules は今受け付けているルールの数 N である。Reserve の名前は制御ソケットの形を
	// 変えないために残す
	RuleCap int `json:"rule_cap"`
	Reserve int `json:"reserve"`
	Rules   int `json:"rules"`
	// Refusals は拒否の累計である。起点は DoctorRuntimeState.RefusalsSince
	Refusals []DoctorRefusal `json:"refusals,omitempty"`
}

// DoctorRefusal はルール 1 本の 1 つの理由の拒否の累計である。
type DoctorRefusal struct {
	RuleID string `json:"rule_id"`
	// Reason は budget、rule_cap、reserve、floor、spare のいずれか(設計文書 7a.10 節)
	Reason resource.Reason `json:"reason"`
	Count  uint64          `json:"count"`
}
