package agent

import (
	"time"

	"github.com/rahanahu/wgft/internal/agent/credentials"
)

// カーネルモードの dataplane を読んだ結果(設計文書 10.2c 節の「カーネルモードの証拠の読み方」)。
// 稼働中のエージェントは制御ソケットの doctor の応答にこの形を載せ、停止中の agent doctor は
// ReadKernel で同じ形を直接読む。読む関数は 1 つで、どちらもそれを使う。判定はしない。どの事実から
// どの状態を選ぶかは CLI が決める。

// DoctorKernel はカーネルモードの dataplane の 3 つの面である。
type DoctorKernel struct {
	Interface  DoctorKernelInterface  `json:"interface"`
	Table      DoctorKernelTable      `json:"table"`
	Forwarding DoctorKernelForwarding `json:"forwarding"`
}

// Ownership の値。internal/dataplane/linuxkernel/wg の Ownership を、Linux の外でも読める語にしたもの。
const (
	KernelOwnershipAbsent       = "absent"
	KernelOwnershipCurrent      = "current"
	KernelOwnershipPrevious     = "previous"
	KernelOwnershipForeign      = "foreign"
	KernelOwnershipKeyless      = "keyless"
	KernelOwnershipNotWireGuard = "not_wireguard"
)

// DoctorKernelInterface はエージェントの WireGuard インタフェースである。
type DoctorKernelInterface struct {
	// Name はインタフェースの名前である
	Name string `json:"name"`
	// ReadError は、リンクそのものを読めなかった理由である。値があるとき、残りの項目は意味を持たない
	ReadError string `json:"read_error,omitempty"`
	// Exists、Kind、Up は権限なしで読める(リンクの属性)。
	Exists bool   `json:"exists"`
	Kind   string `json:"kind,omitempty"`
	Up     bool   `json:"up"`
	// NeedsNetAdmin は、鍵とピアを CAP_NET_ADMIN なしには読めなかったことである。このとき Ownership
	// から下の項目は無い
	NeedsNetAdmin bool `json:"needs_net_admin,omitempty"`
	// DeviceError は、鍵とピアを権限以外の理由で読めなかった理由である
	DeviceError string `json:"device_error,omitempty"`
	// Ownership は KernelOwnership* のどれかである。鍵を読めなかった場合は空になる
	Ownership string             `json:"ownership,omitempty"`
	MTU       int                `json:"mtu,omitempty"`
	Addresses []string           `json:"addresses,omitempty"`
	Peers     []DoctorKernelPeer `json:"peers,omitempty"`

	// Declared は、比べる宣言(全体状態の wg 設定)があったかどうかである。無ければ PeerOK と
	// Differs は意味を持たない
	Declared bool `json:"declared"`
	// ServerAddress は vpsd のトンネルアドレスである。宣言から決まる
	ServerAddress string `json:"server_address,omitempty"`
	// PeerOK は、server の公開鍵を持ち、server のトンネルアドレスを AllowedIPs に含むピアがあることである
	PeerOK bool `json:"peer_ok"`
	// Differs は、宣言と違う点である。30 秒ごとの見直しが食い違いと見るのと同じ関数から来る
	Differs []string `json:"differs,omitempty"`

	// RouteInterface は、server のトンネルアドレスへの経路が向かうインタフェースの名前である。
	// RouteError は経路を読めなかった理由である。どちらも宣言が無ければ無い
	RouteInterface string `json:"route_interface,omitempty"`
	RouteError     string `json:"route_error,omitempty"`
}

// DoctorKernelPeer はインタフェースのピア 1 つである。値を示すだけで、健全さを判定しない。
type DoctorKernelPeer struct {
	PublicKey  string        `json:"public_key"`
	AllowedIPs []string      `json:"allowed_ips,omitempty"`
	Endpoint   string        `json:"endpoint,omitempty"`
	Keepalive  time.Duration `json:"keepalive,omitempty"`
	// LastHandshake は最終ハンドシェイクである。成立していなければゼロ値の時刻になる
	LastHandshake time.Time `json:"last_handshake"`
	RxBytes       int64     `json:"rx_bytes"`
	TxBytes       int64     `json:"tx_bytes"`
}

// 守りの行が欠けたときに開きうる面である(DoctorKernelTable.GuardEffects の値。設計文書 10.2c 節)。drop の
// 行は層になっているので、面は、その面を閉じる行がすべて欠けたときだけ開く。
const (
	// KernelEffectHost は、wgft0 から、wgft が公開していないホストのポートに届きうることである。
	// filter_pre と input の drop の行が両方欠けたときである
	KernelEffectHost = "host"
	// KernelEffectOtherDNAT は、wgft0 から、他のテーブルの DNAT に届きうることである。filter_pre の drop の
	// 行が欠けたときである
	KernelEffectOtherDNAT = "other_dnat"
	// KernelEffectLAN は、wgft0 から、DNAT していないパケットが LAN へ転送されうることである。filter_pre と
	// forward の wgft0 から入るものの drop の行が両方欠けたときである
	KernelEffectLAN = "lan"
	// KernelEffectHairpin は、wgft0 から入ったパケットが wgft0 へ折り返されうることである。forward の
	// wgft0 から wgft0 への drop の行が欠けたときである
	KernelEffectHairpin = "hairpin"
	// KernelEffectToTunnel は、転送したフローの返りでないパケットが wgft0 へ転送されうることである。
	// forward の wgft0 へ出るものの drop の行が欠けたときである
	KernelEffectToTunnel = "to_tunnel"
	// KernelEffectMSS は、ICMP を落とす経路で大きな TCP が止まりうることである
	KernelEffectMSS = "mss"
)

// 欠けた drop の行の面を、残っている行がまだ閉じていることである(DoctorKernelTable.GuardClosed の値)。
const (
	// KernelClosedHostByFilterPre は、input の drop の行が欠けても、filter_pre の drop の行がホストのポートを閉じていることである
	KernelClosedHostByFilterPre = "host_by_filter_pre"
	// KernelClosedHostByInput は、filter_pre の drop の行が欠けても、input の drop の行がホストのポートを閉じていることである
	KernelClosedHostByInput = "host_by_input"
	// KernelClosedLANByFilterPre は、forward の drop の行が欠けても、filter_pre の drop の行が LAN への面を閉じていることである
	KernelClosedLANByFilterPre = "lan_by_filter_pre"
	// KernelClosedLANByForward は、filter_pre の drop の行が欠けても、forward の drop の行が LAN への面を閉じていることである
	KernelClosedLANByForward = "lan_by_forward"
)

// Source の値。比べた材料である。
const (
	// KernelTableFromRecord は、直近の公開の記録と比べたことである
	KernelTableFromRecord = "record"
	// KernelTableFromDeclaration は、記録が無く、全体状態の宣言から導ける範囲だけを比べたことである
	KernelTableFromDeclaration = "declaration"
)

// DoctorKernelTable は table inet wgft_agent と、直近の公開の記録との比較である。
type DoctorKernelTable struct {
	// ReadError はテーブルを読めなかった理由である。NeedsNetAdmin は、それが CAP_NET_ADMIN の
	// 不足によることである
	ReadError     string `json:"read_error,omitempty"`
	NeedsNetAdmin bool   `json:"needs_net_admin,omitempty"`
	Present       bool   `json:"present"`
	// Source は比べた材料で、KernelTableFrom* のどれかである。比べる材料が無ければ空になる
	Source string `json:"source,omitempty"`
	// Generation は記録の元にした全体状態の世代である
	Generation uint64 `json:"generation,omitempty"`
	// Missing は、記録から組む表にあって実際の表に無い行、チェーン、DNAT のうち、欠けると転送が止まる
	// ものである。長くなりすぎない
	// ように先頭のいくつかだけを持ち、MissingCount が全体の数である
	Missing      []string `json:"missing,omitempty"`
	MissingCount int      `json:"missing_count,omitempty"`
	// GuardMissing は、記録から組む表にあって実際の表に無いもののうち、欠けても転送が止まらない行と
	// チェーン(守りの行)である。Missing には入らない。GuardMissingCount が全体の数である
	GuardMissing      []string `json:"guard_missing,omitempty"`
	GuardMissingCount int      `json:"guard_missing_count,omitempty"`
	// GuardEffects は、欠けた守りの行の組み合わせによって開きうる面である。値は KernelEffect* である。
	// GuardClosed は、欠けた drop の行の面を残っている行がまだ閉じていることである。値は KernelClosed* である
	GuardEffects []string `json:"guard_effects,omitempty"`
	GuardClosed  []string `json:"guard_closed,omitempty"`
	// Moved は、記録から組む表の行のうち、同じチェーンの別の位置にあるものである。欠けた行には数えない
	// (設計文書 10.2c 節)。MovedCount が全体の数である
	Moved      []string `json:"moved,omitempty"`
	MovedCount int      `json:"moved_count,omitempty"`
	// Unexpected は、記録に無いのに実際の表にある行、チェーン、DNAT である
	Unexpected      []string `json:"unexpected,omitempty"`
	UnexpectedCount int      `json:"unexpected_count,omitempty"`
	// Rules は記録か宣言から読んだルールごとの状態である。稼働中の応答では、ハートビートの状態は
	// DoctorRuntimeState.Rules にあり、こちらは記録が持つ理由である
	Rules []DoctorRule `json:"rules,omitempty"`
}

// DoctorKernelForwarding はホストの転送の設定である。
type DoctorKernelForwarding struct {
	// IPForward は net.ipv4.ip_forward の値である。読めなければ空で、IPForwardError が理由である
	IPForward      string `json:"ip_forward,omitempty"`
	IPForwardError string `json:"ip_forward_error,omitempty"`
	// RPFilterStrict は、rp_filter が 1 の設定の名前(all、default)である
	RPFilterStrict []string `json:"rp_filter_strict,omitempty"`
	// PolicyDrops は、既定でパケットを落とす他のテーブルの forward のチェーンの場所である
	PolicyDrops []string `json:"policy_drops,omitempty"`
	// PolicyError は他のテーブルを読めなかった理由、PolicyNeedsNetAdmin はそれが CAP_NET_ADMIN の
	// 不足によることである
	PolicyError         string `json:"policy_error,omitempty"`
	PolicyNeedsNetAdmin bool   `json:"policy_needs_net_admin,omitempty"`
}

// maxKernelItems は、Missing と Unexpected に並べる項目の数の上限である。範囲の広いルールや外から
// 加えた多数の行で、応答が大きくなりすぎないようにする。
const maxKernelItems = 8

// ReadKernel は、止まっているエージェントのカーネルの状態を、認証情報ファイル f と WireGuard
// インタフェースの名前 iface から直接読む(設計文書 10.2c 節)。稼働中のエージェントも同じ読み方を
// 使う。カーネルに何も書かない。
func ReadKernel(f *credentials.Credentials, iface string) *DoctorKernel {
	return readKernel(kernelReadInput{iface: iface, creds: f, pub: f.KernelPublication})
}
