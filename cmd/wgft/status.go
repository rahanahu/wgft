package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/internal/vpsd/doctor"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは `wgft status`(設計文書 10.2b 節)を持つ。配置全体が健全かどうかを 1 画面
// で示す要約であり、`server doctor`(doctor.go)のように止まった位置を探す機能ではない。読む
// 節点は 3 つ(`GET /api/v1/rules`、`GET /api/v1/agents`、`GET /api/v1/warnings`)に絞り、
// 新しい管理用 API の節点は追加しない。Rules 行は `GET /api/v1/rules` が既に返す
// `rule_states[].apply_state` と `agent_rule_states` の両方を読むが、どちらも同じ 1 回の応答に
// 含まれる既存のフィールドなので、節点の数は 3 つのままである。判定に使う値の意味と、正常時に
// 内部の値(世代、apply_state の文字列、エンドポイント)を出さないことは design.md 10.2b 節に
// 定める。build tag を持たない。管理用 API を読むだけで、Linux 限定の `server` の一群
// (cmd/wgft/server.go)には属さないためである(design.md 10.2a 節の配置の理由と同じ判断)。
//
// 状態の語彙は healthy・degraded・unknown の 3 つである。証拠が無い項目は、健全でも故障でも
// なく unknown とする。旧い版の server は世代のフィールドを返さないので、これを健全と数えると、
// rolling upgrade の最中にフィールドがまだ返らないだけで健全だと報告してしまう(design.md
// 10.2b 節)。unknown は終了コードを動かさない。degraded だけが動かす(下の exitCode 節を見よ)。

// statusReport は `wgft status --json` の形である。`doctor` の doctorReport とは別の、この
// コマンド専用の模型である(design.md 10.2b 節)。最上位はオブジェクトで、7a.11 節の規則どおり
// 加算的に扱う。項目は増やせるが、名前も意味も変えない。
type statusReport struct {
	Server   serverStatus   `json:"server"`
	Agents   agentsStatus   `json:"agents"`
	Rules    rulesStatus    `json:"rules"`
	Warnings warningsStatus `json:"warnings"`
}

// serverStatus は server 側のデータプレーンへの適用が、宣言に追いついているかどうかである。
// 証拠は `GET /api/v1/rules` の desired_generation、active_generation、apply_error の 3 つだけ
// である(design.md 10.2b 節)。
type serverStatus struct {
	// Status は serverHealthy、serverDegraded、statusUnknown(doctor.go)のいずれかである。
	// bool では unknown を表せないので、この版から文字列にした(design.md 10.2b 節)。
	Status string `json:"status"`
	// Detail は人向けの 1 文で、Status が serverHealthy 以外のときだけ持つ。保証の対象ではない
	// (design.md 10.2b 節)。
	Detail string `json:"detail,omitempty"`
}

// serverStatus.Status の値。healthy と degraded は `wgft status` 独自の語彙で、`server doctor`
// の 5 つの状態(ok/failed/unknown/not_tested/skipped、doctor.go)とは別である。unknown だけは
// 文字列も意味も両方の語彙で共有するので、doctor.go の statusUnknown をそのまま使う。
const (
	serverHealthy  = "healthy"
	serverDegraded = "degraded"
)

// agentsStatus は、登録済みのエージェントを healthy・degraded・unknown の 3 つに数え分けた
// ものである(2026-09-22、所有者の決定)。証拠は `GET /api/v1/agents` の Connected・Tunnel・
// LastHandshake であり、healthy は制御ストリームとトンネルの両方が健全なときだけである。制御
// ストリームが切れている、またはトンネルが failed・error か鮮度の条件を外れているときは
// degraded、トンネルの状態や報告が不明なときは unknown である。トンネルの判定は `server doctor`
// の `tunnel.handshake`(10.2a 節、internal/vpsd/doctor の TunnelHealth)をそのまま呼び、同じ鮮度の規則
// (handshakeStale、3 分)を共有する。以前は Connected だけを見ており、制御ストリームは生きて
// いてもトンネルが死んでいる配置を healthy 側に数えていた(レビューの指摘)。
//
// 3 つの数え分けは有効なエージェントだけが対象である。無効なエージェント(design.md 5.1 節)は
// Disabled に数える(2026-09-24、所有者の決定)。Total は登録済みのエージェントの総数という意味を
// 変えず、Healthy + Degraded + Unknown + Disabled は常に Total に等しい。
type agentsStatus struct {
	Healthy  int `json:"healthy"`
	Degraded int `json:"degraded"`
	Unknown  int `json:"unknown"`
	// Disabled は無効なエージェントの数である。宣言どおりの状態なので終了コードを動かさない。
	// 無効なエージェントが無くても 0 として常に出す。
	Disabled int `json:"disabled"`
	Total    int `json:"total"`
	// Detail は healthy でないエージェントの一覧で、Degraded と Unknown がどちらも 0 のときだけ
	// 空にする。
	Detail string `json:"detail,omitempty"`
}

// rulesStatus は、有効なルールを active・degraded・unknown の 3 つに数え分けたものである。
// 無効なルールは総数に数えない。宣言どおりの状態であり、故障ではないためである(design.md
// 10.2a 節の `rule.enabled` と同じ判断)。持ち主のエージェントが無効なルール(design.md 5.1 節)は
// AgentDisabled に数える(2026-09-24、所有者の決定)。Total は `Rule.Enabled` が真のルールの数と
// いう意味を変えず、Active + Degraded + Unknown + AgentDisabled は常に Total に等しい。
//
// この数え分けは、server 側の適用(rule_states[].apply_state)とエージェント側の転送
// (agent_rule_states)の両方が転送の準備を示していることを要件とする(2026-09-22、所有者の決定)。
// server がルールを公開できていても、エージェントがその target への到達を拒んでいれば
// (WGFT_AGENT_ALLOW_TARGETS など)、1 バイトも転送されない。active はそれ以外の状態を積極的に
// 名乗る唯一の値なので、両方の証拠が揃って初めて active と数える。
type rulesStatus struct {
	// Active は、server が apply_state を active と報告し、かつそのルールの持ち主のエージェントの
	// 鮮度のある報告(agent_rule_states、FreshAgentRuleStatus と同じ鮮度の規則)が ok であるルール
	// の数である(design.md 10.2b 節)。
	Active int `json:"active"`
	// Degraded は、次のいずれかであるルールの数である(design.md 10.2b 節)。
	//   - server が apply_state を pending または not_active と報告している(どちらも
	//     admin.ApplyState が定める既知の値で、報告そのものが証拠として存在する)
	//   - server の apply_state は active だが、そのルールの持ち主のエージェントの鮮度のある
	//     報告が error である
	// いずれも、故障を積極的に観測している。
	Degraded int `json:"degraded"`
	// Unknown は、次のいずれかであるルールの数である(design.md 10.2b 節)。
	//   - rule_states にその行が無い、または server がそもそも rule_states を返さない
	//   - apply_state がこの版の知らない値である(開いた集合、design.md 7a.11 節。知らない値を
	//     故障と決めつけない)
	//   - apply_state は active だが、そのルールの持ち主のエージェントの鮮度のある報告が無い
	//     (一度も報告していない、stream が切れている間の古い報告、報告が
	//     targetReportStale より古い、のいずれか。5.2 節が、切断中のエージェントの最後の報告を
	//     今の状態として描くことを禁じているので、古い報告を degraded にも active にも数えない)
	// いずれも、故障を観測してはいないので Degraded に数えない。
	Unknown int `json:"unknown"`
	// AgentDisabled は、ルール自身は有効で、持ち主のエージェントが無効なルールの数である。
	// 宣言どおりの状態なので終了コードを動かさない。該当が無くても 0 として常に出す。
	// 持ち主のエージェントが登録されていないルールはここに数えず、今までどおり apply_state の
	// not_active として Degraded に数える(design.md 5.1、10.2b 節)。
	AgentDisabled int `json:"agent_disabled"`
	Total         int `json:"total"`
	// Detail は Degraded と Unknown の内訳を 1 行にまとめたもので、どちらも 0 のときだけ空にする。
	Detail string `json:"detail,omitempty"`
}

// warningsStatus は窃取検知の警告の件数である。証拠は `GET /api/v1/warnings` だけであり、
// `AgentInfo.Warnings` は使わない。そちらは窃取検知の警告だけを運ぶエージェント個別の値で、
// 総数を数えるための節点ではない(design.md 10.2b 節)。
type warningsStatus struct {
	Count int `json:"count"`
	// Detail は警告の一覧で、Count が 0 より大きいときだけ持つ。各行は種類・対象のエージェント
	// に加え、`Warning.At` が読めれば発生からの経過も添える。件数だけでは、開いている警告が
	// 30 秒前のものか 3 か月前のものかが運用者にわからないためである(design.md 10.2b 節)。
	Detail string `json:"detail,omitempty"`
}

// statusInput は `wgft status` が読む証拠をまとめたものである。doctor.go の doctorInput と
// 同じ理由で、管理用 API の呼び出しと判定を分け、判定を純粋な関数として試験できるようにする。
type statusInput struct {
	Now      time.Time
	Rules    *admin.BatchResponse
	Agents   []admin.AgentInfo
	Warnings []admin.Warning
}

func newStatusCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Summarize whether the server, agents, rules and warnings look healthy",
		// 引数の数の誤りも「報告を作れなかった」失敗であり、終了コード 2 で終わる。`server doctor`
		// と同じ扱いにする(design.md 10.2b 節)。cobra.NoArgs はエラーの整形で cmd.CommandPath
		// を呼ぶため、ここでは使わない(doctor.go の Args と同じく、自前で数だけを見る)。
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return unavailable(fmt.Errorf("status takes no arguments, got %d", len(args)))
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := adminClient(cmd)
			if err != nil {
				return err
			}
			in := statusInput{Now: time.Now()}
			if in.Rules, err = c.Rules(); err != nil {
				return unavailable(err)
			}
			if in.Agents, err = c.Agents(); err != nil {
				return unavailable(err)
			}
			if in.Warnings, err = c.Warnings(); err != nil {
				return unavailable(err)
			}
			rep := buildStatusReport(in)
			out := cmd.OutOrStdout()
			switch {
			case asJSON:
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(rep); err != nil {
					return unavailable(err)
				}
			default:
				writeStatusReport(out, rep)
			}
			return statusExit(rep)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output as JSON; the stable summary model of this command")
	cmd.Flags().String("admin", "unix:///run/wgft/admin.sock", "admin API address, env WGFT_ADMIN")
	cmd.Flags().String("config", defaultConfigPath, "dotenv config file")
	// フラグの誤りも、引数の数の誤りと同じ理由で終了コード 2 にする(design.md 10.2b 節)。
	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return unavailable(err) })
	return cmd
}

// buildStatusReport は statusInput から 4 行ぶんの判定を組み立てる。doctor.go の各検査と同じ
// 節点しか読まないが、目的が違うので判定はここに独立して持つ。1 つの故障が見つかった時点で
// 「どこで止まったか」を決めつけず、4 つの数を淡々と数えるだけにとどめる。
func buildStatusReport(in statusInput) statusReport {
	return statusReport{
		Server:   serverStatusOf(in.Rules),
		Agents:   agentsStatusOf(in.Agents, in.Now),
		Rules:    rulesStatusOf(in.Rules, in.Agents, in.Now),
		Warnings: warningsStatusOf(in.Warnings, in.Now),
	}
}

// serverStatusOf は GenerationGap(internal/vpsd/doctor)をそのまま使い、doctor の dataplaneCheck と同じ
// 優先順位(apply_error を伴う世代の遅れを先に、次に単独の apply_error)で見る。ただし判定その
// ものは dataplaneCheck と違う。世代の遅れが無く apply_error だけが残る場合、dataplaneCheck は
// これを statusUnknown(reasonRepairFailed)にとどめて `server doctor` の終了コードを 0 のままに
// するが、ここでは degraded にして status の終了コードを 1 にする。順位が同じでも判定を変えて
// よい理由は、問うている範囲が違うからである。`server doctor` はそのルールの転送が今も通っている
// かどうかに答え、公開された値は現行の generation のままなので unknown で足りる。`status` は
// 配置全体の運用の状態に答え、戻れない地点の後の修復が失敗したまま(design.md 7a.3 節)という
// 事実そのものが運用上の劣化なので、degraded として拾う(design.md 10.2b 節)。
// desired_generation と active_generation のどちらかが無ければ、世代の遅れを計算できないので
// unknown にする。ただし apply_error は生成の世代とは別の証拠なので、それが有れば世代が無くても
// degraded と判定する。旧い版の server は 3 つのフィールドをどれも返さないので、この版から、
// 証拠の無いこの場合を healthy ではなく unknown にした(design.md 10.2b 節)。
func serverStatusOf(res *admin.BatchResponse) serverStatus {
	// res is never nil in practice: admin.Client.Rules() always hands back a non-nil
	// *BatchResponse when it returns a nil error (internal/vpsd/admin/client.go), and the RunE
	// above only reaches buildStatusReport after that call has succeeded. This branch is defensive
	// only, kept so this function stays safe to call with a zero statusInput (as the tests do).
	if res == nil {
		return serverStatus{Status: statusUnknown, Detail: "this server does not report apply generations"}
	}
	haveGenerations := res.DesiredGeneration != nil && res.ActiveGeneration != nil
	// この VPS の ip_forward が 0 で、カーネルで転送するルールが止まっていることは、`server doctor` の
	// server.dataplane と同じ判定と同じ文で拾う(design.md 10.2b 節)。
	stop := doctor.IPForwardStop(res)
	if haveGenerations {
		if gap := doctor.GenerationGap(res); gap != "" {
			detail := gap
			if res.ApplyError != "" {
				detail += "; " + res.ApplyError
			}
			if stop != "" {
				detail += "; " + stop
			}
			return serverStatus{Status: serverDegraded, Detail: detail}
		}
	}
	if stop != "" {
		detail := stop
		if res.ApplyError != "" {
			detail += "; " + res.ApplyError
		}
		return serverStatus{Status: serverDegraded, Detail: detail}
	}
	if res.ApplyError != "" {
		return serverStatus{Status: serverDegraded, Detail: res.ApplyError}
	}
	if !haveGenerations {
		return serverStatus{Status: statusUnknown, Detail: "this server does not report apply generations"}
	}
	return serverStatus{Status: serverHealthy}
}

// agentHealthOf は 1 台のエージェントを healthy・degraded・unknown に分類する。制御ストリーム
// (Connected)が切れていること自体が運用上の劣化なので、その場合は degraded とし、agent ls と
// 同じ語り口で最終ハートビートからの経過を添える(internal/vpsd/doctor の Since、ParseWhen を使う)。制御
// ストリームが繋がっている場合だけ、トンネルの健全さを internal/vpsd/doctor の TunnelHealth(`server
// doctor` の `tunnel.handshake`、10.2a 節と同じ判定・同じ鮮度の規則)で見る。制御ストリームが
// 切れている間は、エージェント自身のトンネルの報告がハートビート由来で古くなるため、
// TunnelHealth 自身がこれを healthy 側に倒す(直近のハンドシェイクだけを見る)が、この行の
// 目的では制御ストリームが切れていること自体で既に degraded が決まっているので、その判定を
// 待たずに返す(2026-09-22、所有者の決定)。
func agentHealthOf(a admin.AgentInfo, now time.Time) (status, detail string) {
	if !a.Connected {
		if hb, ok := parseWhen(a.LastHeartbeat); ok {
			return serverDegraded, a.Name + " last seen " + since(now, hb).String() + " ago"
		}
		return serverDegraded, a.Name + " never connected"
	}
	tStatus, _, tDetail, _ := doctor.TunnelHealth(&a, now)
	switch tStatus {
	case statusFailed:
		return serverDegraded, a.Name + " tunnel: " + tDetail
	case statusOK:
		return serverHealthy, ""
	default:
		// TunnelHealth returns only ok, failed and unknown today. A fourth state added later
		// must not be counted as healthy: this command never calls something healthy on
		// evidence it has not read (design.md 10.2b section).
		return statusUnknown, a.Name + " tunnel: " + tDetail
	}
}

// agentsStatusOf は登録済みのエージェントを数える。無効なエージェントは Disabled に数え、有効な
// エージェントだけを agentHealthOf で 3 つに分類する(design.md 10.2b 節)。無効なエージェントも
// stream とトンネルを保つが、宣言どおりに転送しない状態なので、その健全さを配置の劣化に数えない。
func agentsStatusOf(agents []admin.AgentInfo, now time.Time) agentsStatus {
	st := agentsStatus{Total: len(agents)}
	var bad []string
	for _, a := range agents {
		if a.Disabled {
			st.Disabled++
			continue
		}
		status, detail := agentHealthOf(a, now)
		switch status {
		case serverHealthy:
			st.Healthy++
		case statusUnknown:
			st.Unknown++
			bad = append(bad, detail)
		default: // serverDegraded
			st.Degraded++
			bad = append(bad, detail)
		}
	}
	st.Detail = strings.Join(bad, ", ")
	return st
}

// rulesStatusOf は有効なルールを active・degraded・unknown に数え分ける。無効なルールは
// 宣言どおりの状態であり、故障として数えない(このファイル冒頭の rulesStatus のコメントを見よ)。
// rule_states に何も無い(報告を持たない Backend)場合も、個々のルールがその中に載っていない
// 場合も、故障を観測してはいないので unknown にする。かつては両方を active に数えていたが、
// それは証拠の無いことを健全と言っているのと同じだった(design.md 10.2b 節)。
//
// apply_state は admin.ApplyActive・admin.ApplyPending・admin.ApplyNotActive の 3 つを既知の値
// とし、増えうる開いた集合として扱う(design.md 7a.11 節)。既知の非 active(pending、
// not_active)は、server 側の適用そのものが失敗している証拠なので、この時点で degraded に数え、
// エージェント側の証拠は見ない。この版が知らない値(新しい版の server が将来足す値、空文字を
// 含む)は、rule_states にその行が無い場合と同じ unknown に倒す。かつては default 節が active
// 以外を丸ごと degraded に数えており、rolling upgrade で新しい版の server に古い CLI を向けた
// とき、まだ知らない値だけで誤って壊れていると報告していた(design.md 10.2b 節)。
//
// apply_state が active であることは、server がこのルールを公開できたという証拠でしかなく、
// エージェントが実際に target へ届いているという証拠ではない(2026-09-22、所有者の決定)。この
// 場合は、そのルールの持ち主のエージェントの agent_rule_states を、doctor.go の
// FreshAgentRuleStatus と同じ鮮度の規則(接続中、State が空でない、targetReportStale より新しい)
// で読み、次の 3 つに分ける。
//   - 鮮度のある報告が error: 故障を観測しているので degraded
//   - 鮮度のある報告が ok: server とエージェントの両方が転送の準備を報告しているので active
//   - 報告が無い、または鮮度が無い(stream が切れている間の古い報告を含む): 故障を観測しては
//     いないので unknown。5.2 節が、切断中のエージェントの最後の報告を今の状態として描くことを
//     禁じているので、古い報告を degraded にも active にも数えない
//
// 持ち主のエージェントが無効なルールは、apply_state を見る前に agent_disabled に数える(design.md
// 10.2b 節)。そのルールの apply_state は not_active だが、宣言どおりの状態であり、server の適用の
// 失敗ではない。無効かどうかは Agents 行と同じ `GET /api/v1/agents` の応答の Disabled から引く
// ので、読む節点は増えない。旧い版の server は Disabled を返さないので、どのルールも今までどおりに
// 数える。持ち主が登録されていないルールは、agents に行が無いので無効とは読まず、今までどおり
// not_active として degraded に数える。
func rulesStatusOf(res *admin.BatchResponse, agents []admin.AgentInfo, now time.Time) rulesStatus {
	// res is never nil in practice; see the identical note on serverStatusOf above.
	if res == nil {
		return rulesStatus{}
	}
	st := rulesStatus{}
	disabledAgent := map[string]bool{}
	for _, a := range agents {
		if a.Disabled {
			disabledAgent[a.Name] = true
		}
	}
	var bad []string
	// missing counts the rules whose unknown reading comes from having no rule_states evidence at
	// all (the row is absent, or the whole map is, on a Backend without apply reporting).
	// unrecognized counts rules whose rule_states row is present but names an apply_state value
	// this build has never heard of: evidence did arrive, it just is not a value this build
	// recognizes. The two causes get different detail text below, so "unavailable" is never said
	// about a rule that did in fact report something.
	missing, unrecognized := 0, 0
	for _, r := range res.Rules {
		if !r.Enabled {
			continue
		}
		st.Total++
		if disabledAgent[r.Agent] {
			st.AgentDisabled++
			continue
		}
		// A read from a nil map is safe and returns ok == false, so a Backend without apply
		// reporting takes the same "no evidence at all" branch as a rule missing from the map.
		state, ok := res.RuleStates[r.ID]
		switch {
		case !ok:
			st.Unknown++
			missing++
		case state.ApplyState == admin.ApplyPending, state.ApplyState == admin.ApplyNotActive:
			st.Degraded++
			bad = append(bad, short(r.ID)+" "+reasonOr(state.Reason, state.ApplyState))
		case state.ApplyState == admin.ApplyActive:
			// A read from a nil map (a Backend that does not implement AgentRuleStatusBackend at
			// all) is safe and returns the zero admin.AgentRuleStatus, which FreshAgentRuleStatus
			// already treats as "no fresh report" (Connected false, State empty).
			ars, fresh := doctor.FreshAgentRuleStatus(res.AgentRuleStates[r.ID], now)
			switch {
			case fresh && ars.State == proto.StatusError:
				st.Degraded++
				// エージェントが報告した理由は、そのエージェントのホストについて述べる。VPS の上で
				// 読む行なので、どのエージェントの報告かを名指す(design.md 10.2b 節)。
				bad = append(bad, short(r.ID)+" agent "+r.Agent+": "+reasonOr(ars.Reason, "the agent reports an error"))
			case fresh && ars.State == proto.StatusOK:
				st.Active++
			default:
				st.Unknown++
				bad = append(bad, short(r.ID)+" the agent has not confirmed it is forwarding this rule")
			}
		default:
			// A value this build does not know, per the open-set contract above.
			st.Unknown++
			unrecognized++
		}
	}
	if missing > 0 {
		bad = append(bad, fmt.Sprintf("apply state is unavailable for %d rule%s", missing, pluralS(missing)))
	}
	if unrecognized > 0 {
		bad = append(bad, fmt.Sprintf("apply state is an unrecognized value for %d rule%s", unrecognized, pluralS(unrecognized)))
	}
	st.Detail = strings.Join(bad, ", ")
	return st
}

// pluralS returns "s" unless n is exactly 1. Every plural in this file's output builds through
// this one helper; statusExit used to spell it "rule(s)" while rulesStatusOf built "rule%s",
// giving this single command's output two different conventions for the same thing(レビューの
// 指摘)。
func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// warningsStatusOf は `GET /api/v1/warnings` の件数をそのまま数える。AgentInfo.Warnings は
// 使わない(このファイル冒頭の warningsStatus のコメントを見よ)。各行には、種類と対象の
// エージェントに加えて、`Warning.At` が読めれば発生からの経過も添える。件数だけでは、開いている
// 警告が 30 秒前のものか 3 か月前のものかが運用者にわからないためである(design.md 10.2b 節)。
func warningsStatusOf(warnings []admin.Warning, now time.Time) warningsStatus {
	st := warningsStatus{Count: len(warnings)}
	lines := make([]string, 0, len(warnings))
	for _, w := range warnings {
		line := w.Kind + " on " + w.Agent
		if at, ok := parseWhen(w.At); ok {
			line += ", " + since(now, at).String() + " ago"
		}
		lines = append(lines, line)
	}
	st.Detail = strings.Join(lines, ", ")
	return st
}

// --- 人向けの出力 ---

// statusLabelWidth と statusValueWidth は表の桁である。表そのものは保証の対象ではない
// (design.md 7a.11 節)。理由(Detail)が無い行では値のあとの余白を出さない。
const (
	statusLabelWidth = 14
	statusValueWidth = 15
)

// writeStatusReport は 4 行を出す。正常な行は理由を出さず、内部の値(世代、apply_state の
// 文字列、エンドポイント)も出さない(design.md 10.2b 節)。
func writeStatusReport(w io.Writer, rep statusReport) {
	writeStatusLine(w, "Server", rep.Server.Status, rep.Server.Detail)
	writeStatusLine(w, "Agents", agentsValue(rep.Agents), rep.Agents.Detail)
	writeStatusLine(w, "Rules", rulesValue(rep.Rules), rep.Rules.Detail)
	warnings := "none"
	if rep.Warnings.Count > 0 {
		warnings = fmt.Sprintf("%d", rep.Warnings.Count)
	}
	writeStatusLine(w, "Warnings", warnings, rep.Warnings.Detail)
}

// rulesValue は Rules 行の値の列である。すべて active なら "N active" とだけ言う。degraded、
// unknown、agent_disabled が 1 つでもあれば、0 でない数を Total と並べて別々に示す。
// agent_disabled を "N active" の陰に隠さないためである(2026-09-24、所有者の決定)。かつては degraded と unknown を
// まとめて "known"(Active + Degraded)/ Total という 1 つの数に畳んでおり、5 active・2 degraded・
// 1 unknown のような組み合わせが "7 / 8 known" となって、壊れている 2 本が active 側に隠れて
// 読めなくなっていた(レビューの指摘)。この形は、健全でない項目を 1 つでも隠さないことを優先し、
// 値の桁が伸びることを厭わない(design.md 10.2b 節)。
func rulesValue(st rulesStatus) string {
	if st.Degraded == 0 && st.Unknown == 0 && st.AgentDisabled == 0 {
		return fmt.Sprintf("%d active", st.Active)
	}
	parts := []string{fmt.Sprintf("%d active", st.Active)}
	if st.Degraded > 0 {
		parts = append(parts, fmt.Sprintf("%d degraded", st.Degraded))
	}
	if st.Unknown > 0 {
		parts = append(parts, fmt.Sprintf("%d unknown", st.Unknown))
	}
	if st.AgentDisabled > 0 {
		parts = append(parts, fmt.Sprintf("%d agent disabled", st.AgentDisabled))
	}
	return strings.Join(parts, ", ") + fmt.Sprintf(" / %d", st.Total)
}

// agentsValue は Agents 行の値の列である。rulesValue と同じ形にする(design.md 10.2b 節)。
// すべて healthy なら "N / M healthy" とだけ言う。degraded か unknown が 1 つでもあれば、3 つの数を
// 別々に示す。制御ストリームとトンネルの両方を見るようになった 2026-09-22 の改訂までは、この行が
// Connected の数だけを見ており、healthy・degraded・unknown という数え分けを持たなかった。
//
// 無効なエージェントは健康の比から外し、比の後ろに "N disabled" を添える(design.md 10.2b 節、
// 2026-09-24、所有者の決定)。比の分母は有効なエージェントの数である。
func agentsValue(st agentsStatus) string {
	enabled := st.Total - st.Disabled
	var v string
	if st.Degraded == 0 && st.Unknown == 0 {
		v = fmt.Sprintf("%d / %d healthy", st.Healthy, enabled)
	} else {
		parts := []string{fmt.Sprintf("%d healthy", st.Healthy)}
		if st.Degraded > 0 {
			parts = append(parts, fmt.Sprintf("%d degraded", st.Degraded))
		}
		if st.Unknown > 0 {
			parts = append(parts, fmt.Sprintf("%d unknown", st.Unknown))
		}
		v = strings.Join(parts, ", ") + fmt.Sprintf(" / %d", enabled)
	}
	if st.Disabled > 0 {
		v += fmt.Sprintf(", %d disabled", st.Disabled)
	}
	return v
}

// statusExit は報告を終了コードに写す。doctor.go の doctorExit と対になる関数で、doctor と
// 同じく「型を見るだけの exitCode」に載せるため、包まない生の error を返す(design.md 10.2b 節)。
// degraded な項目が 1 つでもあれば非 0 にし、unknown だけの報告は 0 のままにする。旧い版の
// server との rolling upgrade の最中、まだ返らないフィールドだけで監視を鳴らさないためである。
// Agents は Degraded の数だけを見る。制御ストリームが切れている場合とトンネルが健全でない場合の
// 両方がこの数に入り、Unknown はここに数えない(2026-09-22、所有者の決定)。
func statusExit(rep statusReport) error {
	var bad []string
	if rep.Server.Status == serverDegraded {
		bad = append(bad, "server")
	}
	if rep.Rules.Degraded > 0 {
		bad = append(bad, fmt.Sprintf("%d rule%s degraded", rep.Rules.Degraded, pluralS(rep.Rules.Degraded)))
	}
	if rep.Agents.Degraded > 0 {
		bad = append(bad, fmt.Sprintf("%d agent%s degraded", rep.Agents.Degraded, pluralS(rep.Agents.Degraded)))
	}
	if rep.Warnings.Count > 0 {
		bad = append(bad, fmt.Sprintf("%d open warning%s", rep.Warnings.Count, pluralS(rep.Warnings.Count)))
	}
	if len(bad) == 0 {
		return nil
	}
	return fmt.Errorf("the deployment is degraded: %s", strings.Join(bad, ", "))
}

func writeStatusLine(w io.Writer, label, value, detail string) {
	if detail == "" {
		fmt.Fprintf(w, "%-*s%s\n", statusLabelWidth, label, value)
		return
	}
	// %-*s only pads, it never truncates, so a value longer than statusValueWidth (the mixed
	// active/degraded/unknown form of rulesValue can run past it) would otherwise butt straight up
	// against detail with no gap at all. Fall back to a fixed 3-space gap in that case.
	gap := statusValueWidth - len(value)
	if gap < 3 {
		gap = 3
	}
	fmt.Fprintf(w, "%-*s%s%s%s\n", statusLabelWidth, label, value, strings.Repeat(" ", gap), detail)
}
