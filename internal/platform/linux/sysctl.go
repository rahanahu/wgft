//go:build linux

package linux

// sysctl の読み書き:conntrack の UDP タイムアウト、net.ipv4.ip_forward、conntrack テーブルの
// 大きさ(仕様 4, 6.1 節)、エージェントの WireGuard インタフェースの route_localnet(7b.2 節)。
// 書き込むのは WriteIPForward と WriteRouteLocalnet だけである。

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

// ipForwardPath は ReadIPForward と WriteIPForward が読み書きするファイルである。値は IPForwardPath で、
// テストだけが差し替える。
var ipForwardPath = IPForwardPath

// confDir は net.ipv4.conf の下のインタフェースごとの sysctl の置き場である。テストだけが差し替える。
var confDir = "/proc/sys/net/ipv4/conf"

// RouteLocalnetName は、インタフェース iface の route_localnet の sysctl の名前である。ログと理由に出す。
func RouteLocalnetName(iface string) string {
	return "net.ipv4.conf." + iface + ".route_localnet"
}

// routeLocalnetPath は iface の route_localnet のファイルである。インタフェース名はカーネルが受け付ける
// 名前に限る(11a 節の WGFT_WG_INTERFACE の検査)ので、"/" を含まない。"." はそのままファイル名になる。
func routeLocalnetPath(iface string) (string, error) {
	if iface == "" || iface == "." || iface == ".." || strings.ContainsAny(iface, "/\x00") {
		return "", fmt.Errorf("interface name %q cannot name a sysctl", iface)
	}
	return confDir + "/" + iface + "/route_localnet", nil
}

// ReadRouteLocalnet は、インタフェース iface の route_localnet が 1 かどうかを読む(7b.2 節)。値はその
// インタフェースだけのもので、all の値は合わせない。インタフェースが無ければ誤りを返す。
func ReadRouteLocalnet(iface string) (bool, error) {
	p, err := routeLocalnetPath(iface)
	if err != nil {
		return false, err
	}
	cur, err := os.ReadFile(p)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(cur)) == "1", nil
}

// WriteRouteLocalnet は、インタフェース iface の route_localnet に on なら 1、そうでなければ 0 を書く
// (7b.2 節)。値はインタフェースと一緒に消えるので、インタフェースを消せば元に戻る。書き込みには
// CAP_NET_ADMIN が要る。
func WriteRouteLocalnet(iface string, on bool) error {
	p, err := routeLocalnetPath(iface)
	if err != nil {
		return err
	}
	v := "0\n"
	if on {
		v = "1\n"
	}
	return os.WriteFile(p, []byte(v), 0)
}

// ReadIPForward は net.ipv4.ip_forward が 1 かどうかを読む。
func ReadIPForward() (on bool, err error) {
	cur, err := os.ReadFile(ipForwardPath)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(cur)) == "1", nil
}

// WriteIPForward は net.ipv4.ip_forward に 1 を書く。読み取り専用の /proc や、seccomp か LSM で
// 塞がれている場合は誤りを返す。
func WriteIPForward() error {
	return os.WriteFile(ipForwardPath, []byte("1\n"), 0)
}

// ReadIPForwardValue は net.ipv4.ip_forward の値を、前後の空白を除いた文字列で読む。書き込みも、
// 書けるかの probe もしない。撤去が今の値を示すのに使う(仕様 10.3 節)。
func ReadIPForwardValue() (string, error) {
	cur, err := os.ReadFile(ipForwardPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(cur)), nil
}

// IPForwardStatus は net.ipv4.ip_forward を書き込まずに読む、読み取り専用の検査
// (`server check` コマンド、仕様 6.1 節)。value が "1" でなければ、WriteIPForward の実際の
// 書き込みと同じ開き方(O_WRONLY で開いて書かずに閉じる)で書けるかを probe し、開けなければ
// openErr にその理由を返す(value が "1" のときは probe せず openErr は nil)。
func IPForwardStatus() (value string, openErr error, err error) {
	value, err = ReadIPForwardValue()
	if err != nil {
		return "", nil, err
	}
	if value == "1" {
		return value, nil, nil
	}
	f, oerr := os.OpenFile(ipForwardPath, os.O_WRONLY, 0)
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
