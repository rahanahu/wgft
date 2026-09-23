package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/flock"
	"github.com/rahanahu/wgft/internal/resource"
)

// このファイルは `wgft agent doctor`(設計文書 10.2c 節)を持つ。エージェントを動かしている
// ホストの上で、そのホストでしか分からない事実を調べる。`server doctor`(10.2a 節)が server から
// 見た転送の経路に答えるのに対し、こちらはエージェントのローカルの実行環境と現在の状態に答える。
//
// このファイルは、エージェントが止まっていても成立する検査を持つ。10.2c 節の表で「停止中」が
// 「成立しない」の行、つまり稼働中のプロセスの制御ソケットからしか取れない検査は
// agentdoctorlive.go にある。
//
// 検査は副作用を持たない。認証情報ファイルは credentials.Load を通さずに読む。Load は読み取りに
// 続けて Windows の DACL を締め直すからである(10.2c 節の「能動的に試す範囲」)。稼働の判定には
// flock.Inspect を使い、ロックファイルを作らない。稼働中のエージェントへは、その制御ソケットに
// 1 行の doctor を送って読むだけである。
//
// `agent` の一群は build tag を持たないので、このファイルも持たない(10.2c 節の「置き場所」)。
// 副作用なしには判定できない OS 固有の判定だけを agentdoctor_unix.go と agentdoctor_windows.go に
// 分けてある。

// 検査の識別子。10.2c 節の表の「検査の ID」の列である。`server doctor` の checkCredentials と
// agent.credentials という同じ文字列を持つが、別のコマンドの別の模型に属する。10.2c 節はこの
// 衝突を承知の上で同じ id を定めている。
const (
	agentCheckPlatform     = "host.platform"
	agentCheckPrivileges   = "host.privileges"
	agentCheckInterfaces   = "host.interfaces"
	agentCheckHostResolve  = "host.resolve"
	agentCheckCredentials  = "agent.credentials"
	agentCheckProcess      = "agent.process"
	agentCheckLastState    = "agent.last_state"
	agentCheckControl      = "agent.control"
	agentCheckStreamConn   = "stream.connection"
	agentCheckStreamBackfl = "stream.backoff"
	agentCheckStreamLive   = "stream.liveness"
	agentCheckWGResolve    = "tunnel.resolve"
	agentCheckTunnelLocal  = "tunnel.local"
	agentCheckWatchdog     = "tunnel.watchdog"
	agentCheckTransfer     = "tunnel.transfer"
	agentCheckListeners    = "relay.listeners"
	agentCheckSessions     = "relay.sessions"
	agentCheckRefusals     = "relay.refusals"
	agentCheckAllowTargets = "relay.allow_targets"
)

// 検査のまとまり。人向けの出力の見出しになる(10.2c 節の「出力の形」)。
const (
	agentGroupHost        = "Host"
	agentGroupCredentials = "Credentials"
	agentGroupConnection  = "Connection"
	agentGroupTunnel      = "Tunnel"
	agentGroupRelay       = "Relay"
)

// 理由の符号。JSON の "reason" の値であり、機械向けの保証である(設計文書 10.2c 節の
// 「機械向けの出力」、7a.11 節)。1 つの符号は 1 つの事実だけを表し、どの検査に付いても同じ事実を
// 指す。agent.credentials、agent.process、agent.control が OK でないために SKIPPED になった検査は、
// その検査の符号をそのまま持つ。この規則の外の SKIPPED は自分の事実の符号を持ち、中継が無いための
// relay.* の SKIPPED は tunnel.local の符号ではなく no_relay を持つ。一覧は 10.2c 節の表にあり、TestAgentDoctorReasonsMatchTheDesign が照合する。ここにあるのは、エージェントが
// 止まっていても成立する検査が使う符号である。稼働中のプロセスから読む検査の符号は
// agentdoctorlive.go にある。
const (
	// agentReasonNotRunning は、このデータディレクトリのロックを持つプロセスが無いことである。
	agentReasonNotRunning = "agent_not_running"
	// agentReasonResolveFailed は、ホスト名の解決に失敗した場合である(10.2c 節が定める符号)。
	agentReasonResolveFailed = "resolve_failed"
	// agentReasonNoLastState は、agent.json が最後に処理した全体状態を持たない場合である。停止中の
	// rotate-key も全体状態を消すので、一度も受け取っていないとは限らない。稼働中のエージェントが
	// 全体状態をまだ持たないためにトンネルが無いことは、別の符号 agentReasonFullStatePending で表す。
	agentReasonNoLastState = "no_last_state"
	// agentReasonNoWGEndpoint は、全体状態はあるが WireGuard のピアの宛先が空の場合である。
	agentReasonNoWGEndpoint = "no_wg_endpoint"
	// agentReasonCredentialsMissing は、認証情報ファイルが無い場合である。
	agentReasonCredentialsMissing = "credentials_missing"
	// agentReasonCredentialsUnreadable は、認証情報ファイルがあるのに権限で読めない場合である。
	agentReasonCredentialsUnreadable = "credentials_unreadable"
	// agentReasonCredentialsMalformed は、認証情報ファイルを JSON として読めない場合である。
	agentReasonCredentialsMalformed = "credentials_malformed"
	// agentReasonNotRegistered は、認証情報ファイルはあるが登録が済んでいない場合である。
	agentReasonNotRegistered = "not_registered"
	// agentReasonNotRunning と違い、agentReasonLockUnreadable はロックファイルそのものを読めない
	// 場合である。稼働中か停止中かを判定できない。agent.process がこの符号を持つ実行では、稼働中の
	// プロセスから読む検査も、手前の失敗の符号としてこれを持つ。
	agentReasonLockUnreadable = "lock_unreadable"
	// agentReasonPermissionDenied は、診断に要る権限が呼び出し元に無い場合である。
	agentReasonPermissionDenied = "permission_denied"
	// agentReasonPermissionNotDetermined は、権限を副作用なしに判定できない場合である。Windows の
	// 「新しいファイルを作れるか」が当たる(10.2c 節)。
	agentReasonPermissionNotDetermined = "permission_not_determined"
	// agentReasonInterfacesUnreadable は、このホストのインタフェースを読めなかった場合である。
	agentReasonInterfacesUnreadable = "interfaces_unreadable"
	// agentReasonConfigUnreadable は、設定ファイルがあるのに権限で読めない場合である。診断は
	// 続けるが、そのファイルが決める値に依る所見は示せない(10.2c 節)。
	agentReasonConfigUnreadable = "config_unreadable"
	// agentReasonRunningAsRoot は、root で実行したために、エージェント自身の利用者が権限で証拠に
	// 届くかどうかを答えられない場合である。root はファイルのパーミッションを迂回するので、読めた
	// ことはエージェントの利用者について何も述べない(10.2c 節)。
	agentReasonRunningAsRoot = "running_as_root"
)

// agentCheckOrder は 10.2c 節の表の並びである。人向けの出力はこの順に、群ごとにまとめて出す。
var agentCheckOrder = []string{
	agentCheckPlatform, agentCheckPrivileges, agentCheckInterfaces, agentCheckHostResolve,
	agentCheckCredentials, agentCheckProcess, agentCheckLastState,
	agentCheckControl, agentCheckStreamConn, agentCheckStreamBackfl, agentCheckStreamLive,
	agentCheckWGResolve, agentCheckTunnelLocal, agentCheckWatchdog, agentCheckTransfer,
	agentCheckListeners, agentCheckSessions, agentCheckRefusals, agentCheckAllowTargets,
}

// agentDoctorCheck は 1 つの検査の結果である。`server doctor` の checkReport とは別の型にして
// ある。10.2c 節が、運用者が読む出力も機械が読む模型もこのコマンド専用のものだと定めているため
// である。
type agentDoctorCheck struct {
	ID     string
	Group  string
	Label  string
	Status string
	Reason string
	// Detail と Next は人向けの文であり、保証の対象ではない(設計文書 7a.11 節)。
	Detail string
	Next   string
	// verdict は、この検査が総合判定と終了コード 1 を動かすかどうかである。10.2c 節の表の
	// 「総合判定」の列であり、動かすのは agent.credentials、agent.process、tunnel.local、
	// relay.listeners の 4 つだけである。
	verdict bool
	// evidenceUnreachable は、10.2c 節の層 2 に当たる実行である。呼び出し元が権限で証拠に届かず、
	// 診断そのものが成立しなかったことを表し、終了コード 2 に倒す。状態の語とは別のものとして
	// 扱う(同節)。
	evidenceUnreachable bool
	// valueOnly は、この検査が値だけを示し、合否を持たないことである。人向けの出力だけが読む
	// 内部の印であり、`--json` には出さない(10.2c 節、2026-09-24 の所有者の決定)。
	valueOnly bool
}

// agentDoctorReport は 1 回の診断の結果全体である。
type agentDoctorReport struct {
	CheckedAt time.Time
	// DataDir は、この報告が答えるデータディレクトリである。
	DataDir   string
	Checks    []agentDoctorCheck
	History   string
	NotTested []notTested
}

// accessResult は、ある権限を持つかどうかの判定である。副作用なしには判定できない場合を、成功
// でも失敗でもない値として持つ(10.2c 節の「判定できない場合」)。
type accessResult int

const (
	// accessNotDetermined は、副作用なしには判定できなかった状態である。零値にしてあるのは、
	// 判定を落とした呼び出し側が、判定できなかった場合を成功と読み違えないためである。
	accessNotDetermined accessResult = iota
	accessAllowed
	accessDenied
)

// agentDoctorInput は診断が読む証拠の出どころである。OS を読む入口を差し替えられるようにして
// あるのは、10.2c 節が要求する表のテストが、判定できない場合や名前解決の失敗を場面として
// 並べられるようにするためである。
type agentDoctorInput struct {
	Now             time.Time
	DataDir         string
	CredentialsPath string
	Version         string
	Platform        string
	Limits          resource.Limits
	// MemoryLimitEnv は GOMEMLIMIT の値である。設定されている配置では applyMemoryLimit が
	// debug.SetMemoryLimit を呼ばずランタイムに任せるので、フロー数の上限から計算した値は
	// 当たらない(10.2c 節の「示す値の定め方」)。
	MemoryLimitEnv string
	// User は実行している利用者を表す文である。
	User string
	// ConfigPath は設定ファイルの場所である。
	ConfigPath string
	// ConfigUnreadable は、設定ファイルがあるのに権限で読めなかった誤りである。読めた場合と
	// ファイルが無い場合は nil である。ファイルが無い配置は正しいので、誤りとして扱わない。
	ConfigUnreadable error
	// DataDirAssumed は、設定ファイルを読めなかったためにデータディレクトリを既定値から取った
	// ことである。フラグと環境変数の値は設定ファイルより優先するので、そちらから取れた実行では
	// 偽である。真の実行では、読めなかったファイルが別のディレクトリを指している場合があり、
	// 報告が別の場所について述べていることになる。
	DataDirAssumed bool

	// Inspect はロックファイルの状態を読む。既定は flock.Inspect で、ロックファイルを作らない。
	Inspect func(statePath string) (flock.State, error)
	// Resolve はホスト名を解決する。既定はこのホストの resolver である。
	Resolve func(ctx context.Context, host string) ([]string, error)
	// Interfaces はこのホストのインタフェースを読む。
	Interfaces func() ([]net.Interface, error)
	// Readable は、そのパスを読めるかどうかを開いて判定する。
	Readable func(path string, dir bool) (accessResult, error)
	// DirCreateAccess は、そのディレクトリに新しいファイルを作れるかどうかを、作らずに判定する。
	// Windows では判定できないので accessNotDetermined を返す(10.2c 節)。
	DirCreateAccess func(dir string) (accessResult, error)
	// Dial は稼働中のエージェントの制御ソケットに繋ぐ。既定は Unix ソケットへの接続である。
	Dial func(path string) (net.Conn, error)
	// Euid は呼び出し元の実効 uid を返す。既定は os.Geteuid で、Windows では -1 を返す。0 の
	// 実行では host.privileges が判定できない側に倒れる(10.2c 節)。
	Euid func() int
}

// resolveTimeout は名前解決を待つ長さである。診断はトラブルの最中に繰り返し使うので、応答しない
// resolver で黙って止まらないようにする。
const resolveTimeout = 5 * time.Second

// withDefaults は、差し替えられていない入口を OS を読む既定で埋める。
func (in agentDoctorInput) withDefaults() agentDoctorInput {
	if in.Inspect == nil {
		in.Inspect = flock.Inspect
	}
	if in.Resolve == nil {
		in.Resolve = net.DefaultResolver.LookupHost
	}
	if in.Interfaces == nil {
		in.Interfaces = net.Interfaces
	}
	if in.Readable == nil {
		in.Readable = readableAccess
	}
	if in.DirCreateAccess == nil {
		in.DirCreateAccess = dirCreateAccess
	}
	if in.Dial == nil {
		in.Dial = dialAgentControl
	}
	if in.Euid == nil {
		in.Euid = os.Geteuid
	}
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	return in
}

func newAgentDoctorCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "diagnose the agent's own state and environment; agent host; reads only local evidence, running or stopped",
		// 引数の数の誤りも「報告を作れなかった」失敗であり、終了コード 2 で終わる(10.2c 節)。
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.NoArgs(cmd, args); err != nil {
				return unavailable(err)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			in, err := agentDoctorInputFrom(cmd)
			if err != nil {
				return err
			}
			rep := agentDiagnose(in)
			if asJSON {
				// --json は終了コードを変えない。報告の中の status と終了コードは、同じ
				// agentDoctorVerdict から決まる(10.2c 節)。
				if err := writeAgentDoctorJSON(cmd.OutOrStdout(), rep); err != nil {
					return unavailable(err)
				}
			} else {
				writeAgentDoctorReport(cmd.OutOrStdout(), rep)
			}
			return agentDoctorExit(rep)
		},
	}
	fl := cmd.Flags()
	fl.BoolVar(&asJSON, "json", false, "output as JSON; the stable diagnostic model of this command")
	fl.String("data-dir", defaultDataDir(), "data dir, env WGFT_DATA_DIR; holds agent.json")
	// フロー数の上限は、メモリのソフト上限の予測に要る。エージェントが読むのと同じ設定を同じ
	// 経路で読まなければ、予測が当たらない。
	registerLimitFlags(fl)
	fl.String("config", agentConfigPath, "dotenv config file")
	// フラグの誤りも、引数の数の誤りと同じく報告を作れなかった失敗である。
	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return unavailable(err) })
	return cmd
}

// agentDoctorInputFrom は、設定から証拠の出どころを決める。認証情報ファイルの場所は rotate-key
// と同じ経路、つまり WGFT_DATA_DIR、--data-dir、agent.env で決める(10.2c 節)。
//
// 設定ファイルを権限で読めないことは、報告を拒む理由ではなく診断の結果である(10.2c 節の層 2)。
// 読めない実行では、フラグと環境変数と既定から設定を解決して診断を続け、読めなかったことを
// host.privileges と host.platform の所見にする。`agent run` の側は同じ場合に起動を拒む。設定を
// 読めないまま転送を始める常駐プロセスは、宣言された設定で動いていないためである。
func agentDoctorInputFrom(cmd *cobra.Command) (agentDoctorInput, error) {
	configPath := resolveConfigPath(cmd, agentConfigPath)
	file, cfgErr := parseDotenv(configPath)
	if cfgErr != nil && !errors.Is(cfgErr, fs.ErrPermission) {
		// 構文の誤りは設定の値そのものの誤りであり、権限で証拠に届かない場合ではない。他の
		// コマンドと同じく設定の拒否として終了コード 3 で止まる(11a、11b 節)。
		return agentDoctorInput{}, cfgErr
	}
	if cfgErr != nil {
		// 拒否の文面はこの診断の所見には長すぎる。errors.Is で見分けた後は、包まれている
		// もとの誤りだけを持つ。
		if u := errors.Unwrap(cfgErr); u != nil {
			cfgErr = u
		}
		file = map[string]string{}
	}
	c := resolveConfig(cmd, agentSpecs(), configPath, file)
	dir := strings.TrimSpace(c.str("WGFT_DATA_DIR"))
	if dir == "" {
		return agentDoctorInput{}, configErrorf("WGFT_DATA_DIR", "is empty; give the directory that holds agent.json")
	}
	limits, err := limitsFromConfig(c)
	if err != nil {
		return agentDoctorInput{}, err
	}
	return agentDoctorInput{
		Now:              time.Now(),
		DataDir:          dir,
		CredentialsPath:  joinPath(dir, "agent.json"),
		Version:          effectiveVersion(),
		Platform:         runtime.GOOS + "/" + runtime.GOARCH,
		Limits:           limits,
		MemoryLimitEnv:   os.Getenv("GOMEMLIMIT"),
		User:             runningUserText(),
		ConfigPath:       configPath,
		ConfigUnreadable: cfgErr,
		DataDirAssumed:   cfgErr != nil && c.source("WGFT_DATA_DIR") == "default",
	}, nil
}

// agentDoctorVerdict は報告の総合判定である。10.2c 節が定める 3 つの層のうち、層 2 は層 1 に優先
// する。終了コード 2 は診断の結果を信頼できないことを表すので、診断が成立していないまま総合判定を
// failed として返さない。UNKNOWN、NOT TESTED、SKIPPED だけでは ok のままにする。
//
// 終了コードと --json の最上位の status は、どちらもこの関数から決まる。2 か所で判定を持つと、
// --json を付けたかどうかで答えが食い違いうる。
func agentDoctorVerdict(rep agentDoctorReport) string {
	failed := false
	for _, c := range rep.Checks {
		if c.evidenceUnreachable {
			return statusUnknown
		}
		if c.verdict && c.Status == statusFailed {
			failed = true
		}
	}
	if failed {
		return statusFailed
	}
	return statusOK
}

// agentDoctorExit は報告を終了コードに写す。ok は 0、failed は 1、unknown は 2 である(10.2c 節)。
func agentDoctorExit(rep agentDoctorReport) error {
	var failed, unreachable []string
	for _, c := range rep.Checks {
		if c.evidenceUnreachable {
			unreachable = append(unreachable, c.Label)
		}
		if c.verdict && c.Status == statusFailed {
			failed = append(failed, c.Label)
		}
	}
	switch agentDoctorVerdict(rep) {
	case statusUnknown:
		return unavailable(fmt.Errorf("the diagnosis is incomplete: %s could not be read with this command's permissions; run it as the user the agent runs as", strings.Join(unreachable, ", ")))
	case statusFailed:
		return fmt.Errorf("this host's agent cannot forward traffic as it stands: %s", strings.Join(failed, ", "))
	}
	return nil
}

// agentDiagnose は検査一式を組み立てる。証拠は 2 か所から取る(10.2c 節)。静的で永続する側は
// 認証情報ファイルと OS であり、動的で今だけの側は稼働中のプロセスの制御ソケットである。
func agentDiagnose(in agentDoctorInput) agentDoctorReport {
	in = in.withDefaults()
	cred := readAgentCredentials(in.CredentialsPath)
	run := inspectAgentProcess(in)
	live := readAgentLive(in, run)
	checks := []agentDoctorCheck{
		agentPlatformCheck(in),
		agentPrivilegesCheck(in),
		agentInterfacesCheck(in),
		agentEndpointResolveCheck(in, cred),
		agentCredentialsCheck(in, cred),
		agentProcessCheck(in, run),
		agentLastStateCheck(in, cred),
		agentWGResolveCheck(in, cred),
	}
	checks = append(checks, agentLiveChecks(in, run, live)...)
	sort.SliceStable(checks, func(i, j int) bool {
		return agentCheckIndex(checks[i].ID) < agentCheckIndex(checks[j].ID)
	})
	return agentDoctorReport{
		CheckedAt: in.Now,
		DataDir:   absDataDir(in.DataDir),
		Checks:    checks,
		History: "this command only evaluates the current state. To find when this agent stopped working, read its log on this host " +
			"with journalctl -u wgft-agent, or docker logs for a container, and the server log on the VPS.",
		NotTested: agentNotTested(),
	}
}

// absDataDir は、報告が答えるデータディレクトリを絶対パスの正規形で返す(10.2c 節)。同じ
// ディレクトリを相対パスや .. を含むパスで指定しても、機械が読む値を変えないためである。絶対パスに
// できない場合は正規化だけを行う。
func absDataDir(dir string) string {
	if abs, err := filepath.Abs(dir); err == nil {
		return abs
	}
	return filepath.Clean(dir)
}

func agentCheckIndex(id string) int {
	for i, v := range agentCheckOrder {
		if v == id {
			return i
		}
	}
	return len(agentCheckOrder)
}

// --- 証拠の読み取り ---

// credState は認証情報ファイルの読み取りの結果である。10.2c 節は、読み取りの誤りから
// errors.Is で os.ErrNotExist と os.ErrPermission を判定し、どちらでもなければ壊れた JSON として
// 扱うと定めている。終了コードの層が 3 つで分かれるので、1 つの誤りにまとめない。
type credState int

const (
	credOK credState = iota
	credMissing
	credUnreadable
	credMalformed
)

// agentCredentialsFile は認証情報ファイルの読み取りの結果である。
type agentCredentialsFile struct {
	State credState
	Creds *credentials.Credentials
	Err   error
	Mode  fs.FileMode
	// HasMode は Mode を読めたかどうかである。
	HasMode bool
}

// Registered は登録が済んでいるかどうかである。判定は internal/agent の ensureRegistered と同じく
// 恒久トークンの有無で行う(設計文書 5.1 節)。
func (f agentCredentialsFile) Registered() bool {
	return f.State == credOK && f.Creds != nil && f.Creds.PermanentToken != ""
}

// readAgentCredentials は認証情報ファイルを読む。credentials.Load は使わない。Load は読み取りに
// 続けて secureExisting を呼び、Windows では DACL を毎回書き直すためである。診断が副作用を持たない
// という 10.2c 節の約束を保つには、締め直しを伴わない経路で読む必要がある。
func readAgentCredentials(path string) agentCredentialsFile {
	var out agentCredentialsFile
	b, err := os.ReadFile(path)
	if err != nil {
		out.Err = err
		switch {
		case errors.Is(err, fs.ErrNotExist):
			out.State = credMissing
		case errors.Is(err, fs.ErrPermission):
			out.State = credUnreadable
		default:
			out.State = credMalformed
		}
		return out
	}
	if fi, serr := os.Stat(path); serr == nil {
		out.Mode, out.HasMode = fi.Mode().Perm(), true
	}
	var c credentials.Credentials
	if err := json.Unmarshal(b, &c); err != nil {
		out.Err, out.State = err, credMalformed
		return out
	}
	out.Creds, out.State = &c, credOK
	return out
}

// agentRunState は、このデータディレクトリでエージェントが稼働しているかどうかである。
type agentRunState struct {
	State flock.State
	Err   error
	// PermissionDenied は、ロックファイルを権限で開けなかったことである。10.2c 節の層 2 に
	// 当たるのはこの場合だけで、他の読み取りの誤りは当たらない。
	PermissionDenied bool
}

func (r agentRunState) running() bool { return r.State == flock.Locked }

// undetermined は、稼働中かどうかを判定できなかったかどうかである。
func (r agentRunState) undetermined() bool { return r.Err != nil }

// inspectAgentProcess は稼働中かどうかを判定する。ロックファイルを作らない Inspect を使う
// (10.2c 節、所有者の決定)。Acquire を使う経路は、root が診断を打っただけで root 所有の
// ロックファイルを残し、後から非特権で動くエージェントの起動を塞ぐ。
func inspectAgentProcess(in agentDoctorInput) agentRunState {
	st, err := in.Inspect(in.CredentialsPath)
	return agentRunState{State: st, Err: err, PermissionDenied: err != nil && errors.Is(err, fs.ErrPermission)}
}

// --- Host 群 ---

// agentPlatformCheck は OS、アーキテクチャ、wgft の版、メモリのソフト上限の予測を示す。上限は
// 予測であり、稼働中のエージェントが最後に適用した値ではない。debug.SetMemoryLimit は自分の
// プロセスに対する設定であって、外から読む手段が無いためである(10.2c 節)。
func agentPlatformCheck(in agentDoctorInput) agentDoctorCheck {
	c := agentDoctorCheck{ID: agentCheckPlatform, Group: agentGroupHost, Label: "platform", Status: statusOK}
	head := in.Platform + ", wgft " + in.Version
	if v := strings.TrimSpace(in.MemoryLimitEnv); v != "" {
		// GOMEMLIMIT が設定されている配置では applyMemoryLimit が debug.SetMemoryLimit を
		// 呼ばずランタイムに任せるので、フロー数の上限から計算した値は当たらない。
		c.Detail = head + "; the memory soft limit comes from GOMEMLIMIT=" + v + " in this command's environment, not from the flow caps"
		return c
	}
	if in.ConfigUnreadable != nil {
		// 予測が当たるのは、エージェントが読むのと同じ設定を同じ経路で読めた場合だけである
		// (10.2c 節の「示す値の定め方」)。設定ファイルを読めない実行で既定値から計算した数を
		// 示すと、上限を絞った配置では事実でない数を述べることになる。数を出さずに、出せない
		// 理由を述べる。
		c.Status, c.Reason = statusUnknown, agentReasonConfigUnreadable
		c.Detail = head + "; the memory soft limit is not predicted here: it follows the flow caps, and " + in.ConfigPath +
			", which sets them for the agent, could not be read"
		c.Next = agentSamePrincipalNext
		return c
	}
	c.Detail = fmt.Sprintf("%s; the memory soft limit would be %d MiB, computed here from the flow caps %d UDP and %d TCP, not read from the running agent",
		head, in.Limits.MemoryLimit()>>20, in.Limits.WithDefaults().UDPTotal, in.Limits.WithDefaults().TCPTotal)
	return c
}

// agentPrivilegesCheck は、エージェント自身が要る権限を呼び出し元が持つかどうかを見る。対象は
// 10.2c 節のとおり、データディレクトリを読めること、データディレクトリに新しいファイルを作れる
// こと、agent.json を読めることの 3 つに絞る。agent.json 自体への書き込みは見ない。Save は一時
// ファイルを rename で置き換える方式で、求めるのはディレクトリへの書き込みだからである。
//
// この検査は権限だけを見る。agent.json やデータディレクトリが無いことを失敗にしない。不在という
// 事実は agent.credentials が答える。
//
// root で実行した場合は、拒まれた対象が無ければ UNKNOWN とする。root はパーミッションを迂回する
// ので、この実行ではエージェント自身の利用者が届くかどうかを答えられない(10.2c 節)。
func agentPrivilegesCheck(in agentDoctorInput) agentDoctorCheck {
	c := agentDoctorCheck{ID: agentCheckPrivileges, Group: agentGroupHost, Label: "privileges"}
	var have []string
	var denied []string
	var undetermined []string

	dirExists := false
	if fi, err := os.Stat(in.DataDir); err == nil && fi.IsDir() {
		dirExists = true
	}
	if dirExists {
		switch r, err := in.Readable(in.DataDir, true); r {
		case accessAllowed:
			have = append(have, "the data directory is readable")
		case accessDenied:
			denied = append(denied, "the data directory "+in.DataDir+" cannot be read")
		default:
			undetermined = append(undetermined, "whether the data directory can be read: "+errText(err))
		}
	}
	// データディレクトリが無い実行では、それを作れる親ディレクトリの権限を見る(10.2c 節)。
	createDir, createLabel := in.DataDir, "the data directory"
	if !dirExists {
		createDir = nearestExistingDir(in.DataDir)
		createLabel = "the directory " + createDir + ", which would hold the data directory"
	}
	switch r, err := in.DirCreateAccess(createDir); r {
	case accessAllowed:
		have = append(have, "new files can be created in "+createLabel)
	case accessDenied:
		denied = append(denied, "no new file can be created in "+createLabel)
	default:
		// Windows では unix.Access に当たる呼び出しが無く、ACL を読んで判定を自前で組むほかに
		// 手段が無い。7a.11 節が Windows のエージェントを暫定としているので、その判定は組まない。
		// 黙って OK を返す形にもしない(10.2c 節)。
		undetermined = append(undetermined, "whether new files can be created in "+createLabel+": "+errText(err))
	}
	if _, err := os.Stat(in.CredentialsPath); err == nil {
		switch r, rerr := in.Readable(in.CredentialsPath, false); r {
		case accessAllowed:
			have = append(have, "agent.json is readable")
		case accessDenied:
			denied = append(denied, "agent.json cannot be read")
		default:
			undetermined = append(undetermined, "whether agent.json can be read: "+errText(rerr))
		}
	}
	// 設定ファイルを読める権限も、エージェント自身が要る権限である。エージェントは起動のたびに
	// 同じファイルを読み、読めなければ起動を拒む。無いファイルは正しい配置なので見ない。読めな
	// かった実行だけを、他の対象と同じ層 2 の失敗として並べる(10.2c 節)。
	configDenied := in.ConfigUnreadable != nil
	// sawConfigFile は、ファイル自身の持ち主とパーミッションを読めたかどうかである。読めなかった
	// 実行では、拒んでいるのは上の階層のディレクトリであり、ファイル自身については何も分からない。
	sawConfigFile := false
	if configDenied {
		var facts string
		facts, sawConfigFile = configFilePermFacts(in.ConfigPath)
		denied = append(denied, "the config file "+in.ConfigPath+" cannot be read: "+trimSentenceEnd(errText(in.ConfigUnreadable))+
			"; "+facts+". Its settings were taken from this command's flags, environment and the defaults instead")
	}

	// 所見には、満たした対象も満たさなかった対象も並べる。どこまで読めてどこから権限で読めな
	// かったかを示すほうが、運用者は直せる(10.2c 節)。失敗した対象だけを出すと、読めた対象が
	// 出力から消える。
	parts := append([]string{in.User}, have...)
	parts = append(parts, denied...)
	parts = append(parts, undetermined...)
	c.Detail = strings.Join(parts, "; ")
	switch {
	case len(denied) > 0:
		// 状態は FAILED でよい。この検査は総合判定を動かす 4 つに無いので、終了コードは 1 に
		// ならず、層 2 として 2 になる。状態の語と終了コードは別のものとして扱う(10.2c 節)。
		c.Status, c.Reason, c.evidenceUnreachable = statusFailed, agentReasonPermissionDenied, true
		c.Next = agentSamePrincipalNext
		switch {
		case configDenied && sawConfigFile:
			// エージェントを動かす利用者で実行し直しても読めない配置がある。その場合に残る
			// 原因はファイル自身の持ち主とパーミッションなので、見比べる先を示す。
			c.Next += ". If this is already that user, then the file's own owner, group and mode refuse it, and the detail above names both sides"
		case configDenied:
			// ファイル自身は読めていないので、その持ち主とパーミッションを名指ししない。拒んで
			// いるのは上の階層のディレクトリであり、運用者が見るのもそちらである。
			c.Next += ". If this is already that user, then the refusal is on a directory on the way to the config file rather than on the file itself; read the permissions of each directory in its path"
		}
	case in.Euid() == 0:
		// root はファイルのパーミッションを迂回するので、読めたことはエージェント自身の利用者に
		// ついて何も述べない。OK を返すと、非 root で動くエージェントに対する前提の崩れが健全な
		// 報告に隠れる。エージェントが root で動く配置では前提が満たされているので、FAILED にも
		// 層 2 にもしない(10.2c 節)。root でも拒まれた対象がある実行は、root の迂回が及ばない
		// 拒否という事実があるので、前の分岐で層 2 の FAILED として扱う。
		c.Status, c.Reason = statusUnknown, agentReasonRunningAsRoot
		c.Detail += "; root bypasses file permissions, so this run cannot say whether the user the agent runs as can reach them"
		c.Next = "run this command as the same user as the agent. For the packaged systemd unit, that is wgft: runuser -u wgft -- wgft agent doctor. If the agent itself runs as root, this result is expected"
	case len(undetermined) > 0:
		c.Status, c.Reason = statusUnknown, agentReasonPermissionNotDetermined
		c.Next = "if the agent cannot start, read its log for the first write it fails; this command does not answer it"
	default:
		c.Status = statusOK
	}
	return c
}

// agentAssumedDataDirNote は、データディレクトリを既定値から取った実行に添える句である。設定
// ファイルを読めなかった実行では、そのファイルが別のディレクトリを指している場合があり、この
// 報告は別の場所について述べていることになる。断定する所見にだけ添える。エージェントが登録され
// ているかどうかと稼働しているかどうかは、どのデータディレクトリを見たかで答えが変わる。
func agentAssumedDataDirNote(in agentDoctorInput) string {
	if !in.DataDirAssumed {
		return ""
	}
	return "this answers for " + in.DataDir + ", the default, because " + in.ConfigPath +
		" could not be read here and may name another data directory"
}

// agentSamePrincipalNext は、層 2 に当たる実行に添える次の手である。root での実行し直しは案内
// しない。root はすべて読めるので、host.privileges がエージェント自身の権限ではなく root の権限を
// 答え、前提の崩れそのものを検出できなくなる(10.2c 節)。
const agentSamePrincipalNext = "run this command as the user the agent runs as; it answers for that user's permissions, so another user's answer does not describe the agent"

// agentInterfacesCheck はこのホストのインタフェースとアドレスを示す。
func agentInterfacesCheck(in agentDoctorInput) agentDoctorCheck {
	c := agentDoctorCheck{ID: agentCheckInterfaces, Group: agentGroupHost, Label: "interfaces"}
	ifs, err := in.Interfaces()
	if err != nil {
		c.Status, c.Reason = statusUnknown, agentReasonInterfacesUnreadable
		c.Detail = "this host's network interfaces could not be read: " + errText(err)
		c.Next = "read them with ip addr on Linux, ifconfig on macOS, or ipconfig on Windows"
		return c
	}
	var named []string
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		named = append(named, ifc.Name+" "+addrs[0].String())
		if len(named) == 6 {
			break
		}
	}
	c.Status = statusOK
	c.Detail = fmt.Sprintf("%d interface%s", len(ifs), pluralS(len(ifs)))
	if len(named) > 0 {
		c.Detail += "; up and not loopback: " + strings.Join(named, ", ")
	}
	return c
}

// agentEndpointResolveCheck は、エージェント用 API の宛先のホスト名を実際に解決する。名前の解決は
// 宛先のサービスへ接続を作らないので、読み取りだけという既定に入る(10.2c 節)。解決に失敗しても
// 総合判定は動かさない。解決済みの IP で接続が生きていて転送できる場合があるためである。
func agentEndpointResolveCheck(in agentDoctorInput, cred agentCredentialsFile) agentDoctorCheck {
	c := agentDoctorCheck{ID: agentCheckHostResolve, Group: agentGroupHost, Label: "endpoint resolve"}
	if st, ok := agentSkipForCredentials(cred, "the endpoint"); ok {
		c.Status, c.Reason, c.Detail = st.Status, st.Reason, st.Detail
		return c
	}
	return agentResolveInto(c, in, cred.Creds.Endpoint, "the agent API endpoint")
}

// --- Credentials 群 ---

// agentCredentialsCheck は認証情報ファイルを見る。総合判定を動かす検査である。10.2c 節は、
// ファイルが無いこと、まだ登録していないこと、JSON として読めないことを FAILED として終了コード 1
// に、あるのに権限で読めないことを終了コード 2 に分けている。
func agentCredentialsCheck(in agentDoctorInput, cred agentCredentialsFile) agentDoctorCheck {
	c := agentDoctorCheck{ID: agentCheckCredentials, Group: agentGroupCredentials, Label: "credentials", verdict: true}
	switch cred.State {
	case credMissing:
		c.Status, c.Reason = statusFailed, agentReasonCredentialsMissing
		c.Detail = "there is no credentials file at " + in.CredentialsPath + ", so this host has never registered as an agent"
		// 登録したことがないという断定は、見たディレクトリについてのものである。設定ファイルを
		// 読めずに既定値を使った実行では、登録済みのホストについて偽になりうる。
		if note := agentAssumedDataDirNote(in); note != "" {
			c.Detail += "; " + note
		}
		c.Next = "issue a join string on the VPS with wgft agent join-string --name <agent>, then start the agent with WGFT_JOIN set to it"
		return c
	case credUnreadable:
		// 状態は UNKNOWN にする。証拠であるファイルはあるが、読めないので判定に足りない。
		// 呼び出し元がエージェントと同じ実行主体で動いていないために起きる失敗であり、
		// エージェントが転送を担えるかどうかについては何も述べない(10.2c 節)。
		c.Status, c.Reason, c.evidenceUnreachable = statusUnknown, agentReasonCredentialsUnreadable, true
		c.Detail = "the credentials file at " + in.CredentialsPath + " exists but cannot be read here: " + errText(cred.Err)
		c.Next = agentSamePrincipalNext
		return c
	case credMalformed:
		c.Status, c.Reason = statusFailed, agentReasonCredentialsMalformed
		c.Detail = "the credentials file at " + in.CredentialsPath + " cannot be read as JSON: " + errText(cred.Err)
		c.Next = "the agent cannot start from this file. Keep a copy, remove it, and register again with a fresh join string; the server keeps the old registration until you revoke it"
		return c
	}
	f := cred.Creds
	if f.PermanentToken == "" {
		c.Status, c.Reason = statusFailed, agentReasonNotRegistered
		c.Detail = "the credentials file holds no permanent token, so this host has not registered with a server yet"
		c.Next = "issue a join string on the VPS with wgft agent join-string --name <agent>, then start the agent with WGFT_JOIN set to it"
		return c
	}
	c.Status = statusOK
	// agent.json から読んだ値は、稼働中でも停止中でも保存した時点の値なので、`agent ls` および
	// 10.2a 節と同じ last: の接頭辞を付け、今の観測と区別する(10.2c 節)。
	parts := []string{fmt.Sprintf("last: registered as %q to %s", f.Name, orDash(f.Endpoint))}
	if f.CertSHA256 != "" {
		parts = append(parts, "pinned to cert sha256:"+shortHash(f.CertSHA256))
	}
	if f.UsedJoinTokenSHA256 != "" {
		parts = append(parts, "joined with token sha256:"+shortHash(f.UsedJoinTokenSHA256))
	}
	if note := credentialsModeNote(cred); note != "" {
		parts = append(parts, note)
	}
	c.Detail = strings.Join(parts, ", ")
	return c
}

// credentialsModeNote は、認証情報ファイルのパーミッションを 1 句で返す。緩いパーミッションは
// 転送を止めないので、この検査の状態は下げない。恒久トークンを他の利用者が読める配置を黙って
// 通さないために、直し方を所見に添えるだけにする。
func credentialsModeNote(cred agentCredentialsFile) string {
	if !cred.HasMode {
		return ""
	}
	if runtime.GOOS == "windows" {
		return ""
	}
	// パーミッションは常に 4 桁で書く。設定ファイルの所見と揃える。
	note := fmt.Sprintf("mode %#04o", cred.Mode)
	if cred.Mode&0o077 != 0 {
		note += ", which lets other local users read the permanent token; tighten it with chmod 0600"
	}
	return note
}

// agentProcessCheck は稼働中かどうかを見る。総合判定を動かす検査である。停止そのものは FAILED と
// して扱う。ユーザー空間の中継を持つエージェントは常駐して転送を担うプロセスであり、止まっている
// 間は 1 バイトも転送しないためである(10.2c 節)。
func agentProcessCheck(in agentDoctorInput, run agentRunState) agentDoctorCheck {
	c := agentDoctorCheck{ID: agentCheckProcess, Group: agentGroupCredentials, Label: "process", verdict: true}
	if run.Err != nil {
		// 稼働中か停止中かを判定できないので、FAILED にはしない。権限で開けない場合は、
		// 次の前提が崩れている実行として終了コード 2 の側に置く(10.2c 節)。
		c.Status, c.Reason = statusUnknown, agentReasonLockUnreadable
		c.evidenceUnreachable = run.PermissionDenied
		c.Detail = "whether an agent is running here could not be determined: " + errText(run.Err)
		c.Next = agentSamePrincipalNext
		if !run.PermissionDenied {
			c.Next = "read the lock file next to the credentials file, " + flock.LockPath(in.CredentialsPath) + ", and why it cannot be opened"
		}
		return c
	}
	switch run.State {
	case flock.Locked:
		c.Status = statusOK
		c.Detail = "an agent process holds the lock next to the credentials file, so one is running for this data directory"
		return c
	case flock.Absent:
		// ロックファイルが無いのは、一度も起動していない場合と、運用者が消した場合がある。
		// 診断はその 2 つを区別できないが、どちらも稼働の証拠が無い点では同じである(10.2c 節)。
		c.Status, c.Reason = statusFailed, agentReasonNotRunning
		c.Detail = "no agent is running for this data directory: there is no lock file at " + flock.LockPath(in.CredentialsPath) +
			", so either no agent has ever started here or the file was removed"
	default:
		c.Status, c.Reason = statusFailed, agentReasonNotRunning
		c.Detail = "no agent is running for this data directory: the lock file at " + flock.LockPath(in.CredentialsPath) + " is there, but no process holds it"
	}
	// 止まっているという断定も、見たディレクトリについてのものである。設定ファイルを読めずに
	// 既定値を使った実行では、別のディレクトリで動いているエージェントについて偽になりうる。
	if note := agentAssumedDataDirNote(in); note != "" {
		c.Detail += "; " + note
	}
	c.Next = "start it and read why it stopped: systemctl status wgft-agent and journalctl -u wgft-agent, or docker ps and docker logs for a container. " +
		"This answers for " + in.DataDir + " alone; an agent running with another WGFT_DATA_DIR is not visible here"
	return c
}

// agentLastStateCheck は、最後に処理した全体状態を示す。総合判定は動かさない。
func agentLastStateCheck(in agentDoctorInput, cred agentCredentialsFile) agentDoctorCheck {
	c := agentDoctorCheck{ID: agentCheckLastState, Group: agentGroupCredentials, Label: "last state"}
	if st, ok := agentSkipForCredentials(cred, "the last full state"); ok {
		c.Status, c.Reason, c.Detail = st.Status, st.Reason, st.Detail
		return c
	}
	ls := cred.Creds.LastState
	if ls == nil {
		c.Status, c.Reason = statusUnknown, agentReasonNoLastState
		c.Detail = "agent.json holds no full state, so this host holds no rules of its own yet"
		c.Next = "start the agent and let it reach the server; the server sends the whole state on every connection"
		return c
	}
	c.Status = statusOK
	c.Detail = fmt.Sprintf("last: generation %d, %d rule%s", ls.Generation, len(ls.Rules), pluralS(len(ls.Rules)))
	if ls.WG.Address != "" {
		c.Detail += ", tunnel address " + ls.WG.Address
	}
	if ls.WG.Endpoint != "" {
		c.Detail += ", peer " + ls.WG.Endpoint
	}
	if ls.WG.MTU > 0 {
		c.Detail += fmt.Sprintf(", mtu %d", ls.WG.MTU)
	}
	return c
}

// --- Tunnel 群 ---

// agentWGResolveCheck は WireGuard のピアの宛先のホスト名を解決する。host.resolve とは別の検査で
// ある。引く名前も障害の意味も違い、10.2a 節が切り分けられずに残した「最終ハンドシェイクが無い」の
// 原因のうち、名前解決そのものの失敗をこの検査が切り分ける(10.2c 節)。
func agentWGResolveCheck(in agentDoctorInput, cred agentCredentialsFile) agentDoctorCheck {
	c := agentDoctorCheck{ID: agentCheckWGResolve, Group: agentGroupTunnel, Label: "wg endpoint resolve"}
	if st, ok := agentSkipForCredentials(cred, "the WireGuard peer's address"); ok {
		c.Status, c.Reason, c.Detail = st.Status, st.Reason, st.Detail
		return c
	}
	ls := cred.Creds.LastState
	if ls == nil {
		// agent.json が全体状態を持たない事実を理由に示す(10.2c 節)。
		c.Status, c.Reason = statusUnknown, agentReasonNoLastState
		c.Detail = "agent.json holds no full state, so this host does not know which WireGuard peer to resolve"
		c.Next = "start the agent and let it reach the server; the peer's address arrives with the full state"
		return c
	}
	if strings.TrimSpace(ls.WG.Endpoint) == "" {
		c.Status, c.Reason = statusUnknown, agentReasonNoWGEndpoint
		c.Detail = "the recorded full state carries no WireGuard peer address, so there is nothing to resolve"
		c.Next = "read the server's WGFT_WG_ENDPOINT on the VPS; the agent takes the peer's address from the state the server sends"
		return c
	}
	return agentResolveInto(c, in, ls.WG.Endpoint, "the WireGuard peer")
}

// --- 稼働中のプロセスからしか取れない検査 ---

// agentLiveOnlyCheck は 10.2c 節の表で「停止中」が「成立しない」の行である。
type agentLiveOnlyCheck struct {
	ID      string
	Group   string
	Label   string
	verdict bool
	// valueOnly は、この検査が値だけを示し、合否を持たないことである(10.2c 節の「動かさない
	// 検査のうち…累計か現在値を述べるだけ」の 6 つ、2026-09-24 の所有者の決定)。健全なエージェント
	// でもこの 6 つは UNKNOWN にしかならないので、人向けの出力では判定済みの検査と分け、大きな
	// 状態語を出さない。値そのものを読めず SKIPPED になる実行では、通常の検査と同じく状態語を出す。
	valueOnly bool
}

// agentLiveOnly は、稼働中のプロセスの制御ソケットからしか取れない検査の並びである。値を入れる
// のは agentdoctorlive.go の agentLiveChecks で、読めなかった実行では 10.2c 節の規則どおり
// SKIPPED として並べる。項目ごと落とす案は採らない。実行の状態によって項目そのものが消えると、
// 機械が処理しにくくなるためである。
var agentLiveOnly = []agentLiveOnlyCheck{
	{ID: agentCheckControl, Group: agentGroupConnection, Label: "control socket"},
	{ID: agentCheckStreamConn, Group: agentGroupConnection, Label: "control connection"},
	{ID: agentCheckStreamBackfl, Group: agentGroupConnection, Label: "reconnect backoff", valueOnly: true},
	{ID: agentCheckStreamLive, Group: agentGroupConnection, Label: "liveness", valueOnly: true},
	{ID: agentCheckTunnelLocal, Group: agentGroupTunnel, Label: "tunnel", verdict: true},
	{ID: agentCheckWatchdog, Group: agentGroupTunnel, Label: "watchdog", valueOnly: true},
	{ID: agentCheckTransfer, Group: agentGroupTunnel, Label: "transfer", valueOnly: true},
	{ID: agentCheckListeners, Group: agentGroupRelay, Label: "listeners", verdict: true},
	{ID: agentCheckSessions, Group: agentGroupRelay, Label: "sessions", valueOnly: true},
	{ID: agentCheckRefusals, Group: agentGroupRelay, Label: "refusals", valueOnly: true},
	{ID: agentCheckAllowTargets, Group: agentGroupRelay, Label: "target allowlist"},
}

// agentAllowTargetsState は、宛先の許可一覧だけの例外を当てる。停止中は値を示さず UNKNOWN に
// する(10.2c 節、所有者の決定)。設定の値であり、稼働中かどうかに関わらず設定の出どころからは
// 原理的に読めるので、証拠になりうるものはあるが判定には使えないという UNKNOWN の定義に当たる。
// agent.env と CLI 自身の環境変数から組み立てて次の起動で効く値として示す案は採らない。組み立てた
// 値を次に起動するエージェントが実際に読むとは保証できないためである。
//
// 稼働を判定できない実行にも同じ UNKNOWN を当てるが、所見は分ける。同じ報告の agent.process が
// 判定できなかったと述べている横で、この検査だけが止まっていると断定すると、動いているエージェント
// について事実でないことを述べる。
func agentAllowTargetsState(c *agentDoctorCheck, run agentRunState) {
	if run.running() {
		return
	}
	c.Status = statusUnknown
	if run.undetermined() {
		c.Detail = "the allowlist this agent enforces is the one its running process holds, and whether a process holds it now could not be determined"
		c.Next = "settle whether an agent is running first: the process check above says why that could not be read here. " +
			"Once it is settled, the value shown for a running agent is the one it actually enforces, not one rebuilt from the environment"
		return
	}
	c.Detail = "the allowlist this agent enforces is the one its running process holds, and no process holds it now"
	c.Next = "start the agent and re-run this command; the value shown then is the one it actually enforces, not one rebuilt from the environment"
}

// --- 共通の小さな部品 ---

// agentSkipForCredentials は、認証情報ファイルの中身に依る検査の扱いを返す。ファイルが無い場合、
// 権限で読めない場合、壊れている場合、登録が済んでいない場合のいずれでも、その中身に依存する検査は
// SKIPPED とする。試せたはずだが agent.credentials の失敗という手前の失敗によって今回は試せなかった
// 項目であり、SKIPPED の定義に沿う(10.2c 節)。
func agentSkipForCredentials(cred agentCredentialsFile, what string) (agentDoctorCheck, bool) {
	var c agentDoctorCheck
	c.Status = statusSkipped
	switch {
	case cred.State == credMissing:
		c.Reason = agentReasonCredentialsMissing
		c.Detail = "not tested: there is no credentials file, so " + what + " is not recorded anywhere"
	case cred.State == credUnreadable:
		c.Reason = agentReasonCredentialsUnreadable
		c.Detail = "not tested: the credentials file cannot be read here, so " + what + " could not be taken from it"
	case cred.State == credMalformed:
		c.Reason = agentReasonCredentialsMalformed
		c.Detail = "not tested: the credentials file cannot be read as JSON, so " + what + " could not be taken from it"
	case !cred.Registered():
		c.Reason = agentReasonNotRegistered
		c.Detail = "not tested: this host has not registered yet, so " + what + " is not recorded anywhere"
	default:
		return agentDoctorCheck{}, false
	}
	return c, true
}

// agentResolveInto は host:port のホスト名を解決し、その結果を c に入れて返す。解決に失敗しても
// 状態は FAILED ではなく UNKNOWN にし、理由の符号を resolve_failed とする(10.2c 節)。名前解決の
// 失敗は、今後の再接続が危ういという証拠ではあっても、今この瞬間に転送を担えないという証拠では
// ないためである。
func agentResolveInto(c agentDoctorCheck, in agentDoctorInput, endpoint, what string) agentDoctorCheck {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		host = endpoint
	}
	if _, perr := netip.ParseAddr(host); perr == nil {
		c.Status = statusOK
		c.Detail = what + " is the literal address " + host + ", so there is no name to resolve"
		return c
	}
	ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	defer cancel()
	addrs, err := in.Resolve(ctx, host)
	if err != nil || len(addrs) == 0 {
		c.Status, c.Reason = statusUnknown, agentReasonResolveFailed
		c.Detail = "this host cannot resolve " + host + ", the name of " + what + ": " + errText(err)
		c.Next = "fix name resolution on this host. An address resolved earlier can still carry traffic, so this alone does not mean the agent has stopped forwarding"
		return c
	}
	c.Status = statusOK
	c.Detail = host + ", the name of " + what + ", resolves to " + strings.Join(trimAddrs(addrs), ", ")
	return c
}

// trimAddrs は、所見が長くなりすぎないよう先頭のいくつかだけを返す。
func trimAddrs(addrs []string) []string {
	const max = 4
	if len(addrs) <= max {
		return addrs
	}
	return append(addrs[:max:max], fmt.Sprintf("and %d more", len(addrs)-max))
}

// nearestExistingDir は、path から親をたどって最初に見つかる既存のディレクトリを返す。
func nearestExistingDir(path string) string {
	for {
		parent := filepath.Dir(path)
		if parent == path {
			return path
		}
		if fi, err := os.Stat(parent); err == nil && fi.IsDir() {
			return parent
		}
		path = parent
	}
}

// readableAccess は、そのパスを読めるかどうかを実際に開いて判定する。読み取りだけなので副作用を
// 持たない。ディレクトリは、開けるだけでなく中身を 1 件読めることまで見る。
func readableAccess(path string, dir bool) (accessResult, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return accessDenied, err
		}
		return accessNotDetermined, err
	}
	defer f.Close()
	if dir {
		if _, err := f.Readdirnames(1); err != nil && !errors.Is(err, io.EOF) {
			if errors.Is(err, fs.ErrPermission) {
				return accessDenied, err
			}
			return accessNotDetermined, err
		}
	}
	return accessAllowed, nil
}

// runningUserText は、実行している利用者を表す 1 句である。
func runningUserText() string {
	name := ""
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	id := os.Geteuid()
	switch {
	case name != "" && id >= 0:
		return fmt.Sprintf("running as %s, uid %d", name, id)
	case name != "":
		return "running as " + name
	case id >= 0:
		return fmt.Sprintf("running as uid %d", id)
	}
	return "running as an unnamed user"
}

func errText(err error) string {
	if err == nil {
		return "no reason reported"
	}
	return err.Error()
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// upperFirst は先頭の 1 文字を大文字にする。理由の符号に添える次の手は、他の検査と同じく小文字
// で始まる 1 句として持ち、地の文に埋め込むときだけ文として書き起こす。
func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// agentNotTested は、この診断が試していない範囲である。何も壊れていない実行でも必ず出す。黙って
// いると運用者が沈黙を健全と読むためである(10.2a、10.2c 節)。
func agentNotTested() []notTested {
	return []notTested{
		{"the server side", "what the server sees: whether it publishes each rule, what it reads from its own WireGuard, and whether the last " +
			"handshake is healthy. This command never judges that; run wgft server doctor on the VPS for it."},
		{"reaching the vps", "whether this host's line reaches the VPS's WireGuard UDP port and its agent API port. Nothing is dialled towards " +
			"the VPS from here, so a blocked home firewall or ISP does not show up."},
		{"the targets", "the LAN services this agent forwards to. Nothing is dialled from here. A running agent tests TCP targets itself " +
			"every 30s, and its result is what the listeners line above reports; a UDP target cannot be tested at all, so no line here " +
			"answers for one."},
		{"local settings", "the effective value and source of every setting on this host. The agent prints those as its first lines when it " +
			"starts; read them in its log."},
	}
}

// --- 人向けの出力 ---

// writeAgentDoctorReport は検査を群ごとに出す。操作体系は `server doctor`(10.2a 節)に揃える。
// `Result:` の行は持たない。転送の経路を順にたどる形を持たないので、転送が止まった位置を言えない
// ためである(10.2c 節)。値だけを示す検査(agentDoctorCheck.valueOnly)は群から抜き、判定済みの
// 検査の後に別の節として出す(writeAgentDoctorObserved、2026-09-24 の所有者の決定)。
func writeAgentDoctorReport(w io.Writer, rep agentDoctorReport) {
	indent := 2 + labelWidth + 1
	group := ""
	unreachable := false
	var observed []agentDoctorCheck
	for _, c := range rep.Checks {
		unreachable = unreachable || c.evidenceUnreachable
		if c.valueOnly {
			observed = append(observed, c)
			continue
		}
		if c.Group != group {
			fmt.Fprintln(w, c.Group)
			group = c.Group
		}
		writeLine(w, c.Label, statusWord(c.Status), c.Detail)
		// FAILED の所見には必ず次に見るものを添える(10.2a、10.2c 節)。
		if c.Next != "" && c.Status != statusOK {
			fmt.Fprintf(w, "%sCheck: %s\n", strings.Repeat(" ", indent), wrapAt(c.Next, indent+7))
		}
	}
	writeAgentDoctorObserved(w, observed)
	if unreachable {
		// 層 2 に当たる実行でも報告は出す。どこまで読めてどこから権限で読めなかったかを示す
		// ほうが、運用者は直せる(10.2c 節)。
		fmt.Fprintln(w, "\nIncomplete")
		fmt.Fprintf(w, "  %s\n", wrapAt("Some evidence could not be read with this command's permissions, so the lines above do not settle whether this "+
			"agent can forward. "+upperFirst(agentSamePrincipalNext)+".", 2))
	}
	writeHistory(w, rep.History)
	writeNotTested(w, rep.NotTested)
}

// writeAgentDoctorObserved は、値だけを示し合否を持たない検査を「Observed values」の節として
// 出す(10.2c 節、2026-09-24 の所有者の決定)。健全なエージェントでもこの 6 つは UNKNOWN にしか
// ならないので、判定済みの検査と同じ大きな状態語を並べると、運用者がその列をすべて故障と読む。
// この節では、値を読めた実行(状態が UNKNOWN)は状態語を出さずラベルと値だけを示す。値そのものを
// 読めなかった実行は、SKIPPED や、この 6 つがまだ持たない状態が来た場合も含め、判定済みの検査と
// 同じく状態語を出す。値が無いことは、値と取り違えられてはならないためである。
func writeAgentDoctorObserved(w io.Writer, checks []agentDoctorCheck) {
	if len(checks) == 0 {
		return
	}
	indent := 2 + labelWidth + 1
	fmt.Fprintln(w, "\nObserved values")
	for _, c := range checks {
		if c.Status == statusUnknown {
			writeValueLine(w, c.Label, c.Detail)
		} else {
			writeLine(w, c.Label, statusWord(c.Status), c.Detail)
		}
		if c.Next != "" && c.Status != statusOK {
			fmt.Fprintf(w, "%sCheck: %s\n", strings.Repeat(" ", indent), wrapAt(c.Next, indent+7))
		}
	}
}

// writeValueLine は 1 つの観測値を、状態語を出さずにラベルと値だけで出す。桁は writeLine と
// 揃え、状態語の桁が無い分だけ同じ行に収められる detail を長くする。
func writeValueLine(w io.Writer, label, detail string) {
	indent := 2 + labelWidth + 1
	if detail != "" && len(detail) <= inlineDetail+statusWidth {
		fmt.Fprintf(w, "  %-*s %s\n", labelWidth, label, detail)
		return
	}
	fmt.Fprintf(w, "  %s\n", label)
	if detail != "" {
		fmt.Fprintf(w, "%s%s\n", strings.Repeat(" ", indent), wrapAt(detail, indent))
	}
}
