package linux

// sysctl の読み書き:conntrack の UDP タイムアウト、net.ipv4.ip_forward、conntrack テーブルの
// 大きさ(仕様 4, 6.1 節)。EnableIPForward だけが実際に書き込む。

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// UDPTimeouts は VPS の conntrack の UDP タイムアウト 2 値(秒)。全体状態でエージェントに渡す(仕様 4 節)。
type UDPTimeouts struct {
	Timeout       int // nf_conntrack_udp_timeout(既定 30)
	TimeoutStream int // nf_conntrack_udp_timeout_stream(既定 120)
}

// ReadUDPTimeouts は起動時に sysctl を読む。
func ReadUDPTimeouts() (UDPTimeouts, error) {
	t, err := readIntSysctl("/proc/sys/net/netfilter/nf_conntrack_udp_timeout")
	if err != nil {
		return UDPTimeouts{}, err
	}
	ts, err := readIntSysctl("/proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream")
	if err != nil {
		return UDPTimeouts{}, err
	}
	return UDPTimeouts{Timeout: t, TimeoutStream: ts}, nil
}

func readIntSysctl(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w; is the nf_conntrack module loaded", path, err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0, fmt.Errorf("%s value is not an integer: %w", path, err)
	}
	return n, nil
}

// IPForwardPath は net.ipv4.ip_forward の sysctl ファイル(仕様 6.1 節)。
const IPForwardPath = "/proc/sys/net/ipv4/ip_forward"

// EnableIPForward は net.ipv4.ip_forward を確認し、1 でなければ 1 にする(仕様 6.1 節)。
// すでに 1 なら何も書かず changed=false を返す。0→1 に書けたときは changed=true。
// 書き込みに失敗したとき(読み取り専用の /proc、seccomp/LSM で塞がれている場合など)は err を返す。
// 1 にした値を 0 に戻す処理はここには無い(呼び出し側の責務ではなく、そもそも持たない)。
func EnableIPForward() (changed bool, err error) {
	if cur, err := os.ReadFile(IPForwardPath); err == nil && strings.TrimSpace(string(cur)) == "1" {
		return false, nil // すでに 1。触らない
	}
	if err := os.WriteFile(IPForwardPath, []byte("1\n"), 0); err != nil {
		return false, err
	}
	return true, nil
}

// IPForwardStatus は net.ipv4.ip_forward を書き込まずに読む、読み取り専用の検査
// (`server check` コマンド、仕様 6.1 節)。value が "1" でなければ、EnableIPForward の実際の
// 書き込みと同じ開き方(O_WRONLY で開いて書かずに閉じる)で書けるかを probe し、開けなければ
// openErr にその理由を返す(value が "1" のときは probe せず openErr は nil)。
func IPForwardStatus() (value string, openErr error, err error) {
	cur, err := os.ReadFile(IPForwardPath)
	if err != nil {
		return "", nil, err
	}
	value = strings.TrimSpace(string(cur))
	if value == "1" {
		return value, nil, nil
	}
	f, oerr := os.OpenFile(IPForwardPath, os.O_WRONLY, 0)
	if oerr != nil {
		return value, oerr, nil
	}
	f.Close()
	return value, nil, nil
}

// ConntrackMaxPath と ConntrackCountPath は conntrack テーブルの上限と現在の件数(仕様 6.1 節)。
// nf_conntrack が未ロードなら読めない。テストが差し替えられるよう変数にする。
var (
	ConntrackMaxPath   = "/proc/sys/net/netfilter/nf_conntrack_max"
	ConntrackCountPath = "/proc/sys/net/netfilter/nf_conntrack_count"
)

// ConntrackMinMax は、これを下回ると ConntrackUsage.Finding/StartupWarning が警告する
// nf_conntrack_max。メモリの量から出した値ではなく、wgft が運用上の最低の推奨値として定める
// (設計文書 7a.10 節「kernel 側の保護」)。接続元ごとの meter の上限(65535 件)と同じ桁で、
// メモリの小さい VPS の既定値(16384 など)を拾う。
const ConntrackMinMax = 65536

// ConntrackUsage は conntrack テーブルの使用状況。Count は nf_conntrack_count が読めたときだけ有効
// (HaveCount)。
type ConntrackUsage struct {
	Max       int
	Count     int
	HaveCount bool
}

// ReadConntrackUsage は ConntrackMaxPath/ConntrackCountPath を読む。Max が読めなければ err を返す。
// Count は読めなくても(HaveCount=false のまま)成功として返す。
func ReadConntrackUsage() (ConntrackUsage, error) {
	max, err := readProcInt(ConntrackMaxPath)
	if err != nil {
		return ConntrackUsage{}, err
	}
	u := ConntrackUsage{Max: max}
	if count, err := readProcInt(ConntrackCountPath); err == nil {
		u.Count, u.HaveCount = count, true
	}
	return u, nil
}

// Finding は上限が小さいときの警告を作る。足りていれば nil。メモリの figures(MiB、エントリ 1 件の
// バイト数、bucket 数)は出さない。ラボで測った値は kernel の版、設定、エントリの種類で変わるため、
// 提示には使わない(設計文書 7a.10 節「kernel 側の保護」)。65536 は wgft が運用上の最低の推奨値と
// して定める値であり、カーネルにとって正しい値という意味ではない。
func (u ConntrackUsage) Finding() *Finding {
	if u.Max >= ConntrackMinMax {
		return nil
	}
	return &Finding{
		Where:   "nf_conntrack_max",
		Problem: fmt.Sprintf("is low; wgft recommends at least %d", ConntrackMinMax),
		Suggest: []string{
			"a full conntrack table can cause the host to reject new connections",
			fmt.Sprintf("suggested: sysctl -w net.netfilter.nf_conntrack_max=%d", ConntrackMinMax),
			"increasing this limit also increases potential kernel memory use",
			"consider new_flow_rate on public rules to limit new-flow pressure",
		},
	}
}

// StartupWarning は Finding と同じ判定を、server の起動ログ向けの短い 1 行にする。上限が足りて
// いれば空文字を返す。ip_forward と同じ場所(Run が起動時に検査する Findings)で使う
// (設計文書 7a.10 節)。
func (u ConntrackUsage) StartupWarning() string {
	if u.Max >= ConntrackMinMax {
		return ""
	}
	return fmt.Sprintf("nf_conntrack_max=%d is below wgft's recommended minimum of %d; a full conntrack table can reject new connections for the whole host", u.Max, ConntrackMinMax)
}

func readProcInt(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}
