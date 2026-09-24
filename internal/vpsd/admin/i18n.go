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
	"healthOK":   {"すべてのシステムが正常です", "All systems operational"},
	"healthWarn": {"警告があります", "Warnings present"},
	// ヘッダの全体ヘルスの要約は、次の項目を summarySep でつないだものである。オンラインの分母は
	// 有効なエージェントの数で、無効なエージェントは summaryDisabled に分けて、1 台以上のときだけ出す
	// (設計文書 10.1 節)
	"summarySep":      {" ・ ", " · "},
	"summaryOnline":   {"オンライン %d / %d", "%d / %d online"},
	"summaryDisabled": {"無効 %d", "%d disabled"},
	"summaryRules":    {"ルール %d 件", "%d rules"},
	"summaryErrors":   {"エラー %d 件", "%d errors"},
	"summaryWarnings": {"警告 %d 件", "%d warnings"},
	// agents table
	"agents":          {"エージェント", "Agents"},
	"colName":         {"名前", "Name"},
	"colState":        {"状態", "Status"},
	"colTunnelIP":     {"トンネル IP", "Tunnel IP"},
	"colConn":         {"接続情報 (Stream / WG endpoint)", "Stream / WG endpoint"},
	"colGen":          {"世代", "Generation"},
	"colHeartbeat":    {"最終ハートビート", "Last heartbeat"},
	"handshakePrefix": {"ハンドシェイク: ", "Handshake: "},
	"colWarn":         {"警告", "Warnings"},
	"colActions":      {"操作", "Actions"},
	"autorefresh":     {"↻ 5秒ごとに自動更新", "↻ Auto refresh every 5s"},
	"online":          {"オンライン", "Online"},
	"offline":         {"オフライン", "Offline"},
	"tunnelPrefix":    {"トンネル: ", "Tunnel: "},
	"tunnelOK":        {"OK", "OK"},
	"tunnelError":     {"エラー", "Error"},
	"tunnelNone":      {"-", "-"},
	"tunnelStale":     {"最終報告(切断中)", "Last reported; disconnected"},
	"ipMatch":         {"✓ IP 一致", "✓ IP match"},
	"ipMismatch":      {"▲ IP 不一致", "▲ IP mismatch"},
	"ipMismatchAcked": {"IP 不一致 (確認済み)", "IP mismatch, acknowledged"},
	"pending":         {"反映待ち", "Pending"},
	"revoke":          {"削除", "Revoke"},
	"noAgents":        {"エージェントがまだありません。「+ エージェントを追加」から接続文字列を発行してください。", "No agents yet. Use “+ Add agent” to issue a join string."},
	// rules table
	"rules":        {"ルール", "Rules"},
	"gen":          {"世代", "Gen"},
	"colProtoPort": {"プロトコル/ポート", "Protocol / port"},
	"colAgent":     {"エージェント", "Agent"},
	"colDest":      {"宛先", "Destination"},
	"colMode":      {"方式", "Mode"},
	// 方式の列に出す PROXY protocol の印。PROXY protocol は仕様の固有の名前なので、
	// 日本語でもそのままにする。i18n を通すのは、同じ概念を指す他の語がすべて T を
	// 通っているためである。
	"modeProxyProto": {"PROXY", "PROXY"},
	"colDenied":      {"拒否数", "Denied"},
	"colRestrict":    {"接続元制限", "Source restrictions"},
	"applied":        {"適用済み", "Applied"},
	"disabled":       {"無効", "Disabled"},
	"agentOffline":   {"エージェント未接続", "Agent offline"},
	"stateError":     {"エラー", "Error"},
	// server のデータプレーンへの適用状態(設計文書 7a.3 節)
	"serverNotActive": {"サーバーで未適用", "Not active on server"},
	"serverPending":   {"サーバーで反映待ち", "Pending on server"},
	"groupErrN1":      {"エラー %d 件", "%d error"},
	"groupErrN":       {"エラー %d 件", "%d errors"},
	"enable":          {"有効化", "Enable"},
	"disable":         {"無効化", "Disable"},
	"testConn":        {"接続テスト", "Test connection"},
	"delete":          {"削除", "Delete"},
	"allowAll":        {"すべて許可", "Allow all"},
	"noRules":         {"ルールがまだありません。「+ ルールを追加」から作成してください。", "No rules yet. Use “+ Add rule” to create one."},
	"ungrouped":       {"その他", "Ungrouped"},
	"fGroup":          {"グループ", "Group"},
	"fGroupHelp":      {"任意。関連するルールを束ねるラベル(英数と - _ .、32 文字以内)", "Optional label to group related rules. Allowed: letters, digits, - _ ., up to 32 characters"},
	"fNote":           {"説明", "Note"},
	"fNoteHelp":       {"任意。何のためのルールか(120 文字以内)", "Optional. What this rule is for; ≤120 chars"},
	"detailLink":      {"詳細", "Detail"},
	"save":            {"保存", "Save"},
	"denyN":           {"拒否 %d", "%d denied"},
	"allowN":          {"許可のみ %d", "allow-only %d"},
	"rateNewFlow":     {"全体 %[1]d 本/%[2]s", "whole rule %[1]d/%[2]s"},
	"ratePkt":         {"パケット %[1]d 個/%[2]s", "packets %[1]d/%[2]s"},
	"rateSource":      {"接続元ごと %[1]d 本/%[2]s", "per source %[1]d/%[2]s"},
	"noNftTable":      {"(wgft テーブルなし、または nft を読めません)", "no wgft table, or nft not readable"},
	// warnings
	"warningsHead":      {"警告", "Warnings"},
	"warnLinkFmt":       {"警告 %d 件", "%d warnings"},
	"noWarnings":        {"異常なし", "No issues"},
	"dismiss":           {"警告を消す", "Dismiss"},
	"revokeAgent":       {"エージェントを削除", "Revoke agent"},
	"warnMismatchTitle": {"IP の食い違いを検知しました", "IP mismatch detected"},
	"warnMismatchBody":  {"生きている stream の接続元 IP と、最近ハンドシェイクした WireGuard のエンドポイント IP が 2 分以上食い違っています。認証情報 (agent.json) の窃取か二重起動の疑いです。正当な事情(2 拠点から使うなど)なら消してください。", "The live stream's source IP and the recently handshaked WireGuard endpoint IP have differed for over 2 minutes. Possible theft of the credentials in agent.json, or double-start. Dismiss it if this is expected; for example, running from two sites."},
	"warnFlappingTitle": {"IP の往復を検知しました", "IP flapping detected"},
	"warnFlappingBody":  {"同じチャネル(stream の接続元か WireGuard のエンドポイント)の IP が 10 分以内に以前の値へ往復しました。同じ鍵か恒久トークンを 2 か所から使っている疑いです(認証情報の窃取か二重起動)。正当な事情なら消してください。", "The same channel's IP, stream source or WireGuard endpoint, returned to a previous value within 10 minutes. The same key or permanent token is likely used from two places: theft of the credentials in agent.json, or double-start. Dismiss it if this is expected."},
	// confirms
	"confirmRevoke":       {"エージェント %s を削除します。鍵は失効して再接続できなくなり、元に戻せません。使い直すには登録し直す必要があります。ルールの設定は残ります。一時的に止めるだけなら、削除ではなく無効化を使ってください。よいですか?", "Revoke agent %s? Its key stops working and it cannot reconnect; this cannot be undone, and to use it again you must register it again. Its rules are kept. To stop it only for a while, disable it instead."},
	"confirmAgentDisable": {"エージェント %s を無効化します。このエージェントのルールはすべて転送を止め、通信中のセッションも切れます。登録、鍵、ルールの設定は残り、有効化で元に戻ります。よいですか?", "Disable agent %s? Every rule of this agent stops forwarding, and active sessions are cut. Its registration, key and rule settings are kept, and enabling it brings it back."},
	"confirmDelete":       {"ルール %s を削除します。よいですか?", "Delete rule %s?"},
	// forms: add rule
	"addRuleTitle":  {"ルールを追加", "Add rule"},
	"fAgent":        {"エージェント", "Agent"},
	"fProto":        {"プロトコル", "Protocol"},
	"fListenPort":   {"待ち受けポート(例 25565 または 2456-2457)", "Listen port; e.g. 25565 or 2456-2457"},
	"fTarget":       {"宛先(ホスト:ポート)", "Destination: host:port"},
	"fMode":         {"方式", "Mode"},
	"fModeProxy":    {"proxy(TCP のみ)", "proxy, TCP only"},
	"fProxyProto":   {"PROXY protocol ヘッダを送る(proxy のとき)", "Send PROXY protocol header in proxy mode"},
	"fForce":        {"VPS 上で bind 中のポートとの衝突を無視する(--force)", "Ignore conflict with ports bound on the VPS; --force"},
	"submitAddRule": {"ルールを追加", "Add rule"},
	"cancel":        {"キャンセル", "Cancel"},
	"noAgentsOpt":   {"先にエージェントを登録してください", "Register an agent first"},
	// forms: add rule(作り直したフォーム)
	"flowClient":   {"外部クライアント", "Client"},
	"flowAgentN":   {"エージェント", "Agent"},
	"flowTargetN":  {"転送先", "Destination"},
	"flowPortN":    {"ポート", "port"},
	"fListen":      {"受信ポート", "Listen port"},
	"fListenHelp":  {"VPS の公開ポート。外部クライアントが繋ぐ先(例 25565 や 2456-2457)", "Public port on the VPS that clients connect to; e.g. 25565 or 2456-2457"},
	"fDest":        {"転送先", "Destination"},
	"fDestHelp":    {"エージェントが中継する自宅の host:port。受信ポートと違ってもよい。受信ポートが範囲のときは先頭のポートを書き、以降は連番で写る(受信 2456-2457 と宛先 :2456 なら、2457 は :2457 へ)", "Home host:port the agent relays to; it may differ from the listen port. For a listen port range, write the first port and the rest follow in order: listen 2456-2457 with :2456 sends 2457 to :2457"},
	"fAdvanced":    {"転送方式と強制追加", "Forwarding mode and force"},
	"fModeKernel":  {"そのまま転送(既定)", "Forward as-is; default"},
	"fModeKernelH": {"UDP・TCP どちらも。カーネルの DNAT で転送する", "Both UDP and TCP. Forwards via the kernel’s DNAT"},
	"fModeProxyL":  {"実クライアント IP を渡す", "Pass the real client IP"},
	"fModeProxyH":  {"server が TCP を終端し、PROXY protocol で実 IP を渡す(TCP のみ)", "server terminates TCP and passes the real IP via PROXY protocol; TCP only"},
	"fForceNew":    {"VPS で使用中のポートでも強行する", "Proceed even if the port is already in use on the VPS"},
	// forms: add rule(ユーザー空間モード。仕様 6.3 節。kernel/proxy の選択に意味が無いので出さない)
	"fProxyProtoUS":  {"PROXY protocol ヘッダを送る", "Send PROXY protocol header"},
	"fProxyProtoUSH": {"ユーザー空間モードでは、server がすべてのルールを中継します。オンにすると実クライアント IP を自宅側へ渡します。TCP のルールだけに使えます。", "In userspace mode, the server relays every rule. Turning this on passes the real client IP to the home side. Available for TCP rules only."},
	// forms: add agent
	"addAgentTitle": {"エージェントを追加", "Add agent"},
	"fAgentName":    {"エージェント名", "Agent name"},
	"genJoin":       {"接続文字列を生成", "Generate join string"},
	"joinIssued":    {"接続文字列を発行しました(1 回限り・%s まで)", "Join string issued; one-time, valid until %s"},
	"joinHelp":      {"自宅側で WGFT_JOIN にこの文字列を設定して起動してください。名前はこの文字列に紐付いているので、WGFT_NAME は不要です。# を含みます。dotenv のファイルにはクォートせずにそのまま書き、シェルではシングルクォートで囲みます。第三者に共有しないでください。", "On the home side, set WGFT_JOIN to this string and start the agent. The name is bound to the string, so WGFT_NAME is not needed. It contains a #: write it into a dotenv file as it is, without quotes, and wrap it in single quotes in a shell. Do not share it."},
	// check result
	"checkTitle":   {"接続テスト", "Connection test"},
	"checkRuleVia": {"ルール %s(%s 経由)", "Rule %s via %s"},
	"checkOK":      {"経路 OK(VPS → 自宅サービス)", "Path OK: VPS → home service"},
	"checkNote":    {"これは VPS から自宅サービスまでの内側の経路の確認です。外のインターネットからの到達は、実際に外から接続して確かめてください。", "This checks the internal path from the VPS to the home service. Reachability from the public internet must be verified from outside."},
	"reachAgent":   {"自宅サービスに届きません", "Cannot reach the home service"},
	"reachNone":    {"エージェントに繋がりません", "Cannot reach the agent"},
	"reachOther":   {"不達", "Unreachable"},
	"checkFailed":  {"確認できません", "Cannot check"},
	// rule detail page
	"ruleDetailTitle":         {"ルール詳細", "Rule detail"},
	"metaHead":                {"グループと説明", "Group and note"},
	"settingsHead":            {"設定", "Settings"},
	"settingsHelp":            {"グループ、説明、レート制限は、末尾の「保存」でまとめて保存します。", "Group, note, and rate limits are saved together with the Save button at the end."},
	"settingsInvalid":         {"何も保存していません。エラーの出た欄を直してから、保存し直してください。", "Nothing was saved. Correct the fields marked with an error and save again."},
	"settingsConflict":        {"このページを開いた後に、このルールが CLI や別のタブで変更されました。何も保存していません。変更の重なった欄に今の値を示します。入力は残してあるので、確かめてから保存し直してください。", "This rule was changed elsewhere, such as the CLI or another tab, after this page was opened. Nothing was saved. The overlapping fields show the current value; your input is kept, so review it and save again."},
	"settingsRaced":           {"保存の途中で、ルールが別の場所で変更されました。何も保存していません。入力は残してあるので、保存し直してください。", "The rules changed elsewhere while saving, so nothing was saved. Your input is kept; save again."},
	"settingsCurrentFmt":      {"別の場所で変更されています。今の値は %s です。", "Changed elsewhere; the current value is %s."},
	"accessHead":              {"アクセス制御", "Access control"},
	"accessHelp":              {"拒否リストと許可リストの追加と「外す」は、押した時点で反映します。", "Adding to and removing from the deny and allow lists takes effect immediately."},
	"ruleOpsHead":             {"ルール操作", "Rule operations"},
	"denyListHead":            {"拒否リスト", "Deny list"},
	"denyListHelp":            {"最初に評価します。追加すると、その接続元の通信中のセッションも切れます。", "Evaluated first. Adding an entry also cuts that source's active sessions."},
	"allowListHead":           {"許可リスト", "Allow list"},
	"allowListHelp":           {"空ならすべての接続元を許可します。", "When empty, every source is allowed."},
	"listEmpty":               {"(なし)", "none"},
	"addSourcesHelp":          {"1 行に 1 つ書きます。単独のアドレスには /32 を補います。", "One per line. A bare address gets /32."},
	"add":                     {"追加", "Add"},
	"remove":                  {"外す", "Remove"},
	"confirmAllowFirst":       {"許可リストへの最初の追加です。これ以降、リストに無い接続元はすべて拒否され、通信中のセッションも切れます。よいですか?", "This is the first entry in the allow list. After this, every other source will be dropped, including active sessions. Continue?"},
	"confirmAllowLast":        {"許可リストの最後の 1 件を外します。これ以降、すべての接続元を許可します。よいですか?", "This removes the last entry in the allow list. After this, every source will be allowed. Continue?"},
	"rateHead":                {"レート制限", "Rate limits"},
	"rateHelp":                {"超えた分は捨て、一覧の「拒否数」に数えます。瞬間的には、上限を 5 回まで超えて通します。", "Traffic over the limit is dropped and counted in the list's Denied column. Short bursts of up to 5 over the limit are let through."},
	"rateDroppedFmt":          {"拒否 %s 件", "%s dropped"},
	"ratePerSourceHead":       {"1 つの接続元からの新しい接続", "New connections per source"},
	"ratePerSourceHelp":       {"同じ接続元からの接続やスキャンの繰り返しを防ぎます。開いている接続は数えません。", "Protects against repeated connects or scans from one address. Open connections are not counted."},
	"rateNewFlowHead":         {"ルール全体の新しい接続", "New connections for the whole rule"},
	"rateNewFlowHelp":         {"多数の接続元からの同時アクセスを防ぎ、自宅の回線と VPS の接続追跡テーブルを守ります。開いている接続は数えません。", "Protects against many addresses connecting at once, guarding the home line and the VPS connection-tracking table. Open connections are not counted."},
	"ratePacketHead":          {"パケット (通信中のデータも含む)", "Packets, including ongoing traffic"},
	"ratePacketHelp":          {"通信量の急増を防ぎます。値を低くしすぎると、通信中の正規のプレイも一緒に落とします。", "Protects against floods of traffic volume. Setting this too low also drops legitimate ongoing play."},
	"ratePacketDetails":       {"詳細: パケットの制限", "Advanced: packet limit"},
	"rateConnWord":            {"本", "connections"},
	"ratePacketWord":          {"個", "packets"},
	"unitSecond":              {"秒", "second"},
	"unitMinute":              {"分", "minute"},
	"unitHour":                {"時間", "hour"},
	"unitDay":                 {"日", "day"},
	"unitWeek":                {"週", "week"},
	"rateSummaryPerSourceFmt": {"1 つの接続元から 1 %[1]sに %[2]s 本まで", "Up to %[2]s new connections per %[1]s from one source"},
	"rateSummaryWholeFmt":     {"ルール全体で 1 %[1]sに %[2]s 本まで", "Up to %[2]s new connections per %[1]s for the whole rule"},
	"rateSummaryPacketFmt":    {"1 %[1]sに %[2]s 個まで", "Up to %[2]s packets per %[1]s"},
	"noLimit":                 {"制限しない", "No limit"},
	"rateRequired":            {"値を入力するか、「制限しない」を選んでください", "Enter a value, or choose \"No limit\""},
	"packetTCPNoEffectNote":   {"TCP のルールでは、保存した packet_rate の値は効果を持ちません。", "packet_rate is stored but has no effect on TCP rules."},
	"fAddDisabled":            {"無効のまま追加する", "Add in a disabled state"},
	// rule detail page: split / merge
	"splitHead":       {"分割", "Split"},
	"splitHelp":       {"分割する位置を選ぶと、結果の 2 つのルールをすぐ下に示します。実効宛先は変わらないので、通信中のセッションは切れません。", "Choose where to split; the two resulting rules are previewed below. Effective targets don't move, so active sessions stay up."},
	"splitAt":         {"この直前で分ける", "Split just before"},
	"splitSubmit":     {"分割する", "Split"},
	"mergeHead":       {"統合", "Merge"},
	"mergeHelp":       {"隣接していて、エージェント、プロトコル、方式、PROXY protocol、拒否/許可リスト、レート、有効無効がすべて同じルールだけを候補にします。", "Only adjacent rules whose agent, protocol, mode, PROXY protocol, source lists, rates, and enabled state all match are offered as candidates."},
	"mergeWithThis":   {"このルールと統合", "Merge with this rule"},
	"mergeNoNeighbor": {"listen_port が隣接するルールがありません。", "No rule has an adjacent listen_port."},
	"mergeBlockedFmt": {"隣接する %s → %s とは統合できません(%s)。", "Cannot merge with the adjacent %s → %s: %s."},
	"mbAgent":         {"エージェントが違う", "agent differs"},
	"mbProto":         {"プロトコルが違う", "protocol differs"},
	"mbMode":          {"方式が違う", "mode differs"},
	"mbNotAdjacent":   {"隣接していない", "not adjacent"},
	"mbTargetGap":     {"実効宛先が連続していない", "targets are not contiguous"},
	"mbProxyRange":    {"プロキシは範囲に統合できない", "proxy mode is single-port only"},
	"mbDenyList":      {"拒否リストが違う", "deny list differs"},
	"mbAllowList":     {"許可リストが違う", "allow list differs"},
	"mbRates":         {"レート制限が違う", "rate limits differ"},
	"mbEnabled":       {"有効無効が違う", "enabled state differs"},
	// rule export / import
	"exportRules":            {"書き出し", "Export"},
	"importRules":            {"読み込み", "Import"},
	"importTitle":            {"ルールの読み込み", "Import rules"},
	"importChooseFile":       {"ファイル(rules.json)", "File: rules.json"},
	"importChooseFileError":  {"ファイルを選んでください", "Choose a file"},
	"importSubmit":           {"差分を確認", "Check the diff"},
	"importConfirmTitle":     {"読み込みの確認", "Import confirmation"},
	"importAddedN":           {"追加 %d", "Added %d"},
	"importChangedN":         {"変更 %d", "Changed %d"},
	"importDeletedN":         {"削除 %d", "Deleted %d"},
	"importUnchangedN":       {"変わらない %d", "Unchanged %d"},
	"importIssuesHead":       {"適用できません", "Cannot apply"},
	"importDeletedNote":      {"このルールは消えます。通信中のセッションも切れます。", "This rule will be removed; its active sessions are cut."},
	"importApply":            {"適用する", "Apply"},
	"confirmImportApply":     {"削除を含みます。適用しますか?", "This includes deletions. Apply?"},
	"importStale":            {"確認ページを表示した後にルールが変わったため、適用しませんでした。rules.json を作り直して、もう一度読み込んでください。", "The rule set changed after this confirmation page was shown, so nothing was applied. Regenerate rules.json and import it again."},
	"diffFieldAgent":         {"エージェント", "agent"},
	"diffFieldGroup":         {"グループ", "group"},
	"diffFieldNote":          {"説明", "note"},
	"diffFieldProto":         {"プロトコル", "protocol"},
	"diffFieldListenPort":    {"待ち受けポート", "listen port"},
	"diffFieldTarget":        {"宛先", "destination"},
	"diffFieldMode":          {"方式", "mode"},
	"diffFieldProxyProtocol": {"PROXY protocol", "PROXY protocol"},
	"diffFieldDenyList":      {"拒否リスト", "deny list"},
	"diffFieldAllowList":     {"許可リスト", "allow list"},
	"diffFieldNewFlowRate":   {"新規フロー制限", "new-flow rate"},
	"diffFieldPacketRate":    {"パケット制限", "packet rate"},
	"diffFieldPerSourceRate": {"接続元ごとの制限", "per-source rate"},
	"diffFieldEnabled":       {"有効無効", "enabled"},
	"diffValueFmt":           {"%s %s → %s", "%s %s → %s"},
	"diffSetFmt":             {"%s %s", "%s %s"},
	"boolYes":                {"あり", "yes"},
	"boolNo":                 {"なし", "no"},
	// 診断の画面(設計文書 10.2d 節)。検査の見出し、状態の語、群の名前と所見の自由文は
	// 英語のままにするので、ここには持たない。画面の枠の語だけを切り替える。
	"doctorTitle":            {"診断", "Diagnostics"},
	"crumbDashboard":         {"ダッシュボード", "Dashboard"},
	"crumbNav":               {"現在の位置", "Breadcrumb"},
	"doctorIntro":            {"この画面は、server が既に受け取っている観測から組み立てます。開いた時点では、どこへも接続を試しません。", "This page is built from what the server has already observed. Opening it dials nothing."},
	"doctorFinding":          {"所見", "Finding"},
	"doctorHistoryHead":      {"履歴", "History"},
	"doctorNotTestedHead":    {"この診断が試していない範囲", "Not tested by this diagnosis"},
	"doctorCheckedAt":        {"読み取りの時刻:", "Read at"},
	"doctorProbeOnRulePage":  {"疎通の確認は、ルールごとの画面にあります。上の表の行からルールを開くと、その 1 本だけに接続を試せます。", "The end-to-end probe lives on the page of a single rule: open a rule from its row above to dial that rule, and only that rule."},
	"doctorProbeHead":        {"疎通の確認", "End-to-end probe"},
	"doctorProbe":            {"疎通を試す", "Run the probe"},
	"doctorProbeHelp":        {"押したときだけ、この server からトンネルとエージェントを通って宛先へ TCP 接続を 1 本開きます。宛先にはデータを伴わない接続が 1 本届きます。", "Only when pressed, this opens one real TCP connection from this server, through the tunnel and the agent, to the target. The target sees one connection that carries no data."},
	"doctorProbeUnavailable": {"疎通の確認を使えるのは、有効な TCP のルールだけです。UDP は送信だけでは成否が分かりません。", "The probe is available for enabled TCP rules only: a UDP send cannot tell success."},
	// 判定が持つ所見は CLI のために書いてあるので、画面から実行できない案内がそのまま出る。
	// 共有の文は書き換えず、画面の側に 1 文を添える(10.2d 節の改訂の記録)。
	"doctorSourceFilterNote": {
		"この画面には接続元アドレスの入力欄がありません。1 つのアドレスを試すには、VPS で sudo wgft server doctor <ルールの ID> --from <接続元アドレス> を実行してください。ルールの ID は画面の先頭にあります。",
		"This page has no field for a client address. To try one, run sudo wgft server doctor <rule id> --from <client address> on this VPS; the rule ID is at the top of this page.",
	},
	"doctorInternalHead": {"内部の値", "Internal values"},
	"doctorHiddenHead":   {"既定で隠している検査", "Checks hidden by default"},
	// 診断の画面の経路の図。節点の名前と状態の語は英語のままで、ここには置かない(10.2d 節)。
	"doctorNotReached":    {"届いていない", "not reached"},
	"doctorAfterStopAlt":  {"止まった位置より後ろなので、図には状態を出していません", "not shown in the path after the stop"},
	"doctorDisabledAlt":   {"ルールが無効なので、何も転送していません", "the rule is disabled, so nothing is forwarded"},
	"doctorUDPTargetNote": {"リスナーは開いています。UDP の宛先は試していません", "listener open; UDP target not tested"},
	"doctorPathAria":      {"公開側から宛先までの経路", "path from the public port to the target"},
	"doctorAgentPathAria": {"エージェントの状態", "agent state"},
	"doctorRuleCol":       {"ルール", "Rule"},
	"doctorPathCol":       {"経路", "Path"},
	"doctorFindingMore":   {"所見を読む", "Read the finding"},
	"doctorOffPathHead":   {"経路の外の検査", "Checks off the path"},
	"doctorAgentChecks":   {"検査と次に見るもの", "Checks and what to check next"},
	"doctorBanner":        {"server の転送の状態が OK ではありません。すべてのルールに関わります。", "The server's own forwarding is not OK; it concerns every rule."},
	// ダッシュボードのルール一覧の診断の印(設計文書 10.1 節)。%s に入る状態の語と節点の名前は英語のまま
	"dashDiagAlt":          {"診断: %s", "Diagnosis: %s"},
	"dashDiagUnregistered": {"エージェント未登録", "agent not registered"},

	// エージェントの詳細ページ(設計文書 10.1 節)
	"agentDetailTitle":      {"エージェント詳細", "Agent detail"},
	"agentCrumbFmt":         {"エージェント %s", "Agent %s"},
	"agentFieldAddress":     {"トンネル IP", "Tunnel IP"},
	"agentFieldPublicKey":   {"公開鍵", "Public key"},
	"agentFieldStream":      {"stream の接続元", "Stream source"},
	"agentFieldWG":          {"WireGuard のエンドポイント", "WireGuard endpoint"},
	"agentFieldTunnel":      {"トンネル", "Tunnel"},
	"agentFieldHandshake":   {"最終ハンドシェイク", "Last handshake"},
	"agentFieldCreated":     {"登録", "Registered"},
	"agentFieldDisabledAt":  {"無効にした時刻", "Disabled at"},
	"agentDisabledNote":     {"このエージェントは無効です。ルールはすべて転送を止めています。登録、鍵、ルールの設定は残っており、有効化で元に戻ります。", "This agent is disabled. None of its rules forward. Its registration, key and rule settings are kept, and enabling it brings it back."},
	"agentRulesHead":        {"ルール", "Rules"},
	"agentRulesNone":        {"このエージェントを持ち主とするルールはありません。", "No rule belongs to this agent."},
	"dangerZoneHead":        {"危険な操作", "Danger zone"},
	"agentDeleteHead":       {"エージェントの削除", "Revoke this agent"},
	"agentDeleteHelp":       {"削除すると鍵は失効し、このエージェントは再接続できなくなります。元に戻せません。使い直すには、新しい接続文字列で登録し直します。ルールの設定は残ります。一時的に止めるだけなら、削除ではなく上の「無効化」を使ってください。", "Revoking makes its key stop working, and the agent cannot reconnect. This cannot be undone; to use it again, register it again with a new join string. Its rules are kept. To stop it only for a while, use Disable above instead."},
	"agentDeleteConfirmFmt": {"確認のため、エージェントの名前 %s を入力してください", "To confirm, type the agent's name, %s"},
	"agentDeleteMismatch":   {"入力した名前がエージェントの名前と一致しません。何も削除していません。", "The name you typed does not match the agent's name. Nothing was revoked."},
	"agentDeleteFailed":     {"エージェントを削除できませんでした。", "The agent could not be revoked."},
	"agentChangeNotSaved":   {"何も変えていません。", "Nothing was changed."},
	"agentChangeNotApplied": {"変更は保存しましたが、まだ転送の設定に反映していません。server が 30 秒ごとに反映を試し直します。", "The change is saved but not yet applied to forwarding. The server retries every 30 seconds."},

	// ルールの適用状態のうち、持ち主のエージェントが未登録か無効のもの。どちらも故障ではないので
	// 灰色で示す(設計文書 5.1、10.1 節)
	"agentUnregistered": {"エージェント未登録", "Agent not registered"},
	"agentDisabled":     {"エージェント無効", "Agent disabled"},

	// 持ち主のエージェントが無効なルールの診断の画面(設計文書 5.1、10.2a 節)。検査の見出しと理由の
	// 符号(agent enabled、agent_disabled)は他の検査と同じく英語のままにする。
	"doctorAgentDisabledAlt":   {"ルールのエージェントが無効なので、何も転送していません", "the rule's agent is disabled, so nothing is forwarded"},
	"doctorProbeAgentDisabled": {"このルールのエージェントは無効です。無効なエージェントのルールには、疎通の確認を使えません。", "This rule's agent is disabled, and the probe is not available for a rule of a disabled agent."},

	// UDP の宛先の応答の観測(設計文書 10.2a 節「UDP の応答の観測」)。状態の色を持たない控えめな注記
	"doctorUDPLastReply":   {"最後に応答を観測: %s", "last reply seen %s"},
	"doctorUDPNoReply":     {"%sに観測を始めてから、応答を観測していません", "no reply seen since watching began %s"},
	"doctorUDPNotObserved": {"応答を観測できません: %s", "replies are not observed: %s"},
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
