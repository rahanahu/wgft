package main

import (
	"encoding/json"
	"io"
	"time"

	"github.com/rahanahu/wgft/internal/textsafe"
)

// このファイルは `wgft agent doctor --json`(設計文書 10.2c 節の「機械向けの出力」)の模型を持つ。
//
// 模型は人向けの出力と同じ agentDoctorReport から写す。検査を組み立て直さないので、人向けの行と
// JSON の項目は、状態も理由の符号も必ず一致する。
//
// `server doctor --json` の型(internal/vpsd/doctor の Report)は再利用しない。10.2c 節はこの
// コマンド専用の模型と定めており、型を共有すると server 側の変更がこの出力を黙って変える。同じ
// 事実を表すフィールドの名前が揃っていることは、TestAgentDoctorJSONSharesServerDoctorNames が
// 確かめる。

// agentDoctorJSON は報告全体である。最上位をオブジェクトにしてあるのは、後から項目を加えても
// 読み手が壊れないようにするためである(7a.11 節の加算の規則)。
type agentDoctorJSON struct {
	// Status は総合判定で、ok、failed、unknown のいずれかである。終了コードの 0、1、2 に当たる。
	Status string `json:"status"`
	// CheckedAt は診断した時刻で、RFC 3339 の UTC である。
	CheckedAt string `json:"checked_at"`
	// DataDir は、この報告が答えるデータディレクトリである。
	DataDir string `json:"data_dir"`
	// Checks は 10.2c 節の表の検査すべてであり、表の順に並ぶ。
	Checks    []agentDoctorJSONCheck     `json:"checks"`
	History   agentDoctorJSONHistory     `json:"history"`
	NotTested []agentDoctorJSONNotTested `json:"not_tested"`
}

// agentDoctorJSONCheck は 1 つの検査である。
type agentDoctorJSONCheck struct {
	// ID、Status、Reason は機械向けの保証である。Reason は ok の検査では省く。
	ID     string `json:"id"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	// EvidenceUnreachable は、この検査が終了コード 2 に倒す条件に当たったことである。当たった
	// 検査だけが true として持つ。
	EvidenceUnreachable bool `json:"evidence_unreachable,omitempty"`
	// Group、Label、Detail、Next は人向けの文であり、保証の対象ではない(7a.11 節)。
	Group  string `json:"group"`
	Label  string `json:"label"`
	Detail string `json:"detail"`
	Next   string `json:"next,omitempty"`
}

// agentDoctorJSONHistory は履歴の有無である。この版は現在の状態しか見ない。
type agentDoctorJSONHistory struct {
	Available bool   `json:"available"`
	Detail    string `json:"detail"`
}

// agentDoctorJSONNotTested は試していない範囲 1 件である。
type agentDoctorJSONNotTested struct {
	ID     string `json:"id"`
	Detail string `json:"detail"`
}

// agentDoctorJSONOf は報告を模型に写す。
//
// Detail・Next・History.Detail・NotTested[].Detail は、稼働中のエージェントの制御ソケットの
// 応答に由来するとき(RuntimeState を経由するとき)は classifyDoctorReply の
// textsafe.SanitizeStrings で既に無害化されているが、停止中の読み(agent.json の LastState、
// カーネルの状態)に由来するときはまだ無害化されていない。ここで一括して掛けるのは、この模型が
// 実行の状態(稼働中か停止中か)によって守りの有無が変わらないようにするためである。ID・
// Status・Reason・EvidenceUnreachable は c の側で固定の定数から選ばれ、エージェントの文字列を
// 経由しないので、この呼び出しの対象に含めない(design.md 11 節、2026-09-26)。
func agentDoctorJSONOf(rep agentDoctorReport) agentDoctorJSON {
	out := agentDoctorJSON{
		Status:    agentDoctorVerdict(rep),
		CheckedAt: rep.CheckedAt.UTC().Format(time.RFC3339),
		DataDir:   rep.DataDir,
		Checks:    make([]agentDoctorJSONCheck, 0, len(rep.Checks)),
		History:   agentDoctorJSONHistory{Detail: textsafe.SanitizeForTerminal(rep.History)},
		NotTested: make([]agentDoctorJSONNotTested, 0, len(rep.NotTested)),
	}
	for _, c := range rep.Checks {
		out.Checks = append(out.Checks, agentDoctorJSONCheck{
			ID: c.ID, Status: c.Status, Reason: c.Reason, EvidenceUnreachable: c.evidenceUnreachable,
			Group: c.Group, Label: c.Label,
			Detail: textsafe.SanitizeForTerminal(c.Detail), Next: textsafe.SanitizeForTerminal(c.Next),
		})
	}
	for _, n := range rep.NotTested {
		out.NotTested = append(out.NotTested, agentDoctorJSONNotTested{ID: n.ID, Detail: textsafe.SanitizeForTerminal(n.Detail)})
	}
	return out
}

// writeAgentDoctorJSON は模型を書く。字下げは `server doctor --json` に揃える。
func writeAgentDoctorJSON(w io.Writer, rep agentDoctorReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(agentDoctorJSONOf(rep))
}
