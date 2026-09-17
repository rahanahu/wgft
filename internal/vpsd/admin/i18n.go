package admin

import (
	"net/http"
	"strings"
)

// 管理 UI の多言語対応(ja / en)。文字列はサーバ側で描画する。
// 言語の解決順:明示(?lang=)→ クッキー → Accept-Language → ja(運用者は日本語想定)。

const langCookie = "wgft_lang"

var langs = map[string]bool{"ja": true, "en": true}

// tr は キー → 言語 → 文字列。ja を基準に、en を併記する。
var tr = map[string][2]string{
	// [0]=ja, [1]=en
	"subtitle": {"WireGuard Forwarding Tool", "WireGuard Forwarding Tool"},
	"addAgent": {"+ エージェントを追加", "+ Add agent"},
	"addRule":  {"+ ルールを追加", "+ Add rule"},
	"back":     {"← ダッシュボードへ戻る", "← Back to dashboard"},
	"firewall": {"適用中のファイアウォール設定", "Applied firewall configuration"},
	// server info
	"serverHead":  {"サーバー", "Server"},
	"svVersion":   {"バージョン", "Version"},
	"svUptime":    {"稼働", "Uptime"},
	"svMode":      {"転送方式", "Mode"},
	"svEndpoint":  {"エンドポイント", "Endpoint"},
	"svWG":        {"WireGuard", "WireGuard"},
	"svAgentAPI":  {"エージェント API", "Agent API"},
	"svMTU":       {"MTU", "MTU"},
	"svKernel":    {"カーネル", "Kernel"},
	"svNFT":       {"nftables", "nftables"},
	"svIPForward": {"ip_forward", "ip_forward"},
	"svConntrack": {"conntrack UDP", "conntrack UDP"},
	"ipfBywgft":   {"wgft が設定", "set by wgft"},
	"ipfDefault":  {"既定のまま", "unchanged"},
	// health
	"healthOK":    {"すべてのシステムが正常です", "All systems operational"},
	"healthWarn":  {"警告があります", "Warnings present"},
	"summaryOK":   {"オンライン %d / %d ・ ルール %d 件", "%d / %d online · %d rules"},
	"summaryWarn": {"オンライン %d / %d ・ ルール %d 件 ・ 警告 %d 件", "%d / %d online · %d rules · %d warnings"},
	// agents table
	"agents":       {"エージェント", "Agents"},
	"colName":      {"名前", "Name"},
	"colState":     {"状態", "Status"},
	"colTunnelIP":  {"トンネル IP", "Tunnel IP"},
	"colConn":      {"接続情報 (Stream / WG endpoint)", "Connection (Stream / WG endpoint)"},
	"colGen":       {"世代", "Generation"},
	"colHeartbeat": {"最終ハートビート", "Last heartbeat"},
	"colWarn":      {"警告", "Warnings"},
	"colActions":   {"操作", "Actions"},
	"autorefresh":  {"↻ 5秒ごとに自動更新", "↻ Auto refresh every 5s"},
	"online":       {"オンライン", "Online"},
	"offline":      {"オフライン", "Offline"},
	"tunnelPrefix": {"トンネル: ", "Tunnel: "},
	"tunnelOK":     {"OK", "OK"},
	"tunnelError":  {"エラー", "Error"},
	"tunnelNone":   {"-", "-"},
	"ipMatch":      {"✓ IP 一致", "✓ IP match"},
	"ipMismatch":   {"▲ IP 不一致", "▲ IP mismatch"},
	"pending":      {"反映待ち", "Pending"},
	"revoke":       {"無効化", "Revoke"},
	"noAgents":     {"エージェントがまだありません。「+ エージェントを追加」から接続文字列を発行してください。", "No agents yet. Use “+ Add agent” to issue a join string."},
	// rules table
	"rules":         {"ルール", "Rules"},
	"gen":           {"世代", "Gen"},
	"colProtoPort":  {"プロトコル/ポート", "Protocol / port"},
	"colAgent":      {"エージェント", "Agent"},
	"colDest":       {"宛先", "Destination"},
	"colMode":       {"方式", "Mode"},
	"colDenied":     {"拒否数", "Denied"},
	"colRestrict":   {"接続元制限", "Source restrictions"},
	"applied":       {"適用済み", "Applied"},
	"disabled":      {"無効", "Disabled"},
	"enable":        {"有効化", "Enable"},
	"disable":       {"無効化", "Disable"},
	"testConn":      {"接続テスト", "Test connection"},
	"delete":        {"削除", "Delete"},
	"allowAll":      {"すべて許可", "Allow all"},
	"noRules":       {"ルールがまだありません。「+ ルールを追加」から作成してください。", "No rules yet. Use “+ Add rule” to create one."},
	"ungrouped":     {"その他", "Ungrouped"},
	"fGroup":        {"グループ", "Group"},
	"fGroupHelp":    {"任意。関連するルールを束ねるラベル(英数と - _ .、32 文字以内)", "Optional. Label to group related rules (letters, digits, - _ ., ≤32)"},
	"fNote":         {"説明", "Note"},
	"fNoteHelp":     {"任意。何のためのルールか(120 文字以内)", "Optional. What this rule is for (≤120 chars)"},
	"editMeta":      {"編集", "Edit"},
	"editMetaTitle": {"グループ・説明を編集", "Edit group / note"},
	"save":          {"保存", "Save"},
	"denyN":         {"拒否 %d", "%d denied"},
	"allowN":        {"許可のみ %d", "allow-only %d"},
	"rateNewFlow":   {"新規フロー", "new flows"},
	"ratePkt":       {"パケット", "packets"},
	"rateSource":    {"接続元ごと", "per source"},
	"noNftTable":    {"(wgft テーブルなし、または nft を読めません)", "(no wgft table, or nft not readable)"},
	// warnings
	"warningsHead":      {"警告", "Warnings"},
	"noWarnings":        {"異常なし", "No issues"},
	"dismiss":           {"警告を消す", "Dismiss"},
	"revokeAgent":       {"エージェントを無効化", "Revoke agent"},
	"warnMismatchTitle": {"IP の食い違いを検知しました", "IP mismatch detected"},
	"warnMismatchBody":  {"生きている stream の接続元 IP と、最近ハンドシェイクした WireGuard のエンドポイント IP が 2 分以上食い違っています。認証情報 (agent.json) の窃取か二重起動の疑いです。正当な事情(2 拠点から使うなど)なら消してください。", "The live stream's source IP and the recently handshaked WireGuard endpoint IP have differed for over 2 minutes. Possible theft of the credentials (agent.json) or double-start. Dismiss it if this is expected (e.g. running from two sites)."},
	"warnFlappingTitle": {"IP の往復を検知しました", "IP flapping detected"},
	"warnFlappingBody":  {"同じチャネル(stream の接続元か WireGuard のエンドポイント)の IP が 10 分以内に以前の値へ往復しました。同じ鍵か恒久トークンを 2 か所から使っている疑いです(認証情報の窃取か二重起動)。正当な事情なら消してください。", "The same channel (stream source or WireGuard endpoint) IP returned to a previous value within 10 minutes. The same key or permanent token is likely used from two places (theft of the credentials (agent.json) or double-start). Dismiss it if this is expected."},
	// confirms
	"confirmRevoke": {"エージェント %s を無効化します。よいですか?", "Revoke agent %s?"},
	"confirmDelete": {"ルール %s を削除します。よいですか?", "Delete rule %s?"},
	// forms: add rule
	"addRuleTitle":  {"ルールを追加", "Add rule"},
	"fAgent":        {"エージェント", "Agent"},
	"fProto":        {"プロトコル", "Protocol"},
	"fListenPort":   {"待ち受けポート(例 25565 または 2456-2457)", "Listen port (e.g. 25565 or 2456-2457)"},
	"fTarget":       {"宛先(ホスト:ポート)", "Destination (host:port)"},
	"fMode":         {"方式", "Mode"},
	"fModeProxy":    {"proxy(TCP のみ)", "proxy (TCP only)"},
	"fProxyProto":   {"PROXY protocol ヘッダを送る(proxy のとき)", "Send PROXY protocol header (proxy mode)"},
	"fForce":        {"VPS 上で bind 中のポートとの衝突を無視する(--force)", "Ignore conflict with ports bound on the VPS (--force)"},
	"submitAddRule": {"ルールを追加", "Add rule"},
	"cancel":        {"キャンセル", "Cancel"},
	"noAgentsOpt":   {"先にエージェントを登録してください", "Register an agent first"},
	// forms: add rule(作り直したフォーム)
	"flowClient":   {"外部クライアント", "Client"},
	"flowAgentN":   {"エージェント", "Agent"},
	"flowTargetN":  {"転送先", "Destination"},
	"flowPortN":    {"ポート", "port"},
	"fListen":      {"受信ポート", "Listen port"},
	"fListenHelp":  {"VPS の公開ポート。外部クライアントが繋ぐ先(例 25565 や 2456-2457)", "Public port on the VPS that clients connect to (e.g. 25565 or 2456-2457)"},
	"fDest":        {"転送先", "Destination"},
	"fDestHelp":    {"エージェントが中継する自宅の host:port。受信ポートと違ってもよい。受信ポートが範囲のときは先頭のポートを書き、以降は連番で写る(受信 2456-2457 と宛先 :2456 なら、2457 は :2457 へ)", "Home host:port the agent relays to; it may differ from the listen port. For a listen port range, write the first port and the rest follow in order (listen 2456-2457 with :2456 sends 2457 to :2457)"},
	"fAdvanced":    {"転送方式と強制追加", "Forwarding mode and force"},
	"fModeKernel":  {"そのまま転送(既定)", "Forward as-is (default)"},
	"fModeKernelH": {"UDP・TCP どちらも。カーネルの DNAT で転送する", "Both UDP and TCP. Forwards via the kernel’s DNAT"},
	"fModeProxyL":  {"実クライアント IP を渡す", "Pass the real client IP"},
	"fModeProxyH":  {"server が TCP を終端し、PROXY protocol で実 IP を渡す(TCP のみ)", "server terminates TCP and passes the real IP via PROXY protocol (TCP only)"},
	"fForceNew":    {"VPS で使用中のポートでも強行する", "Proceed even if the port is already in use on the VPS"},
	// forms: add rule(ユーザー空間モード。仕様 6.3 節。kernel/proxy の選択に意味が無いので出さない)
	"fProxyProtoUS":  {"PROXY protocol ヘッダを送る", "Send PROXY protocol header"},
	"fProxyProtoUSH": {"ユーザー空間モードでは、server がすべてのルールを中継します。オンにすると実クライアント IP を自宅側へ渡します。TCP のルールだけに使えます。", "In userspace mode, the server relays every rule. Turning this on passes the real client IP to the home side. Available for TCP rules only."},
	// forms: add agent
	"addAgentTitle": {"エージェントを追加", "Add agent"},
	"fAgentName":    {"エージェント名", "Agent name"},
	"genJoin":       {"接続文字列を生成", "Generate join string"},
	"joinIssued":    {"接続文字列を発行しました(1 回限り・%s まで)", "Join string issued (one-time, valid until %s)"},
	"joinHelp":      {"自宅側で WGFT_JOIN にこの文字列を、WGFT_NAME に名前を入れて起動してください。# を含むのでクォートします。第三者に共有しないでください。", "On the home side, set WGFT_JOIN to this string and WGFT_NAME to the name. Quote it (contains #). Do not share it."},
	// check result
	"checkTitle":   {"接続テスト", "Connection test"},
	"checkRuleVia": {"ルール %s(%s 経由)", "Rule %s (via %s)"},
	"checkOK":      {"経路 OK(VPS → 自宅サービス)", "Path OK (VPS → home service)"},
	"checkNote":    {"これは VPS から自宅サービスまでの内側の経路の確認です。外のインターネットからの到達は、実際に外から接続して確かめてください。", "This checks the internal path from the VPS to the home service. Reachability from the public internet must be verified from outside."},
	"reachAgent":   {"自宅サービスに届きません", "Cannot reach the home service"},
	"reachNone":    {"エージェントに繋がりません", "Cannot reach the agent"},
	"reachOther":   {"不達", "Unreachable"},
	"checkFailed":  {"確認できません", "Cannot check"},
}

// T はキーの訳を返す。未知のキーはキーそのものを返す。
func T(locale, key string) string {
	v, ok := tr[key]
	if !ok {
		return key
	}
	if locale == "en" {
		return v[1]
	}
	return v[0]
}

// resolveLocale は言語を決める。?lang= があればそれを採用してクッキーに残す。
func resolveLocale(w http.ResponseWriter, r *http.Request) string {
	if l := r.URL.Query().Get("lang"); langs[l] {
		http.SetCookie(w, &http.Cookie{Name: langCookie, Value: l, Path: "/", MaxAge: 365 * 24 * 3600, SameSite: http.SameSiteLaxMode})
		return l
	}
	if c, err := r.Cookie(langCookie); err == nil && langs[c.Value] {
		return c.Value
	}
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Accept-Language")), "en") {
		return "en"
	}
	return "ja"
}
