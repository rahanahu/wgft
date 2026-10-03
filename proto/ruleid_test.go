package proto

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestRuleIDLimits は、ルールの ID の長さと文字の検査(仕様 5.3 節)を確かめる。長さは UTF-8 の
// バイトで数え、文字は unicode.IsGraphic が真のものだけを受ける。日本語、ASCII の空白、ASCII 以外の
// 空白(Zs)は受け、ID は変えない。制御文字、行と段落の区切り(Zl、Zp)、書式の文字(Cf)は拒む。
// 変異の確認:長さの比較を文字数に変えると「43 文字で 129 バイト」が通って落ちる。IsGraphic の検査を
// 外すと制御文字の行が通って落ちる。IsPrint に変えると ASCII 以外の空白の行が拒まれて落ちる。
// utf8.ValidString の検査を外すと不正な UTF-8 の行が別の文言になって落ちる。
func TestRuleIDLimits(t *testing.T) {
	ascii := func(n int) string { return strings.Repeat("a", n) }
	tests := []struct {
		name    string
		id      string
		wantErr string // 空なら成功を期待
	}{
		{"ASCII で 128 バイト", ascii(128), ""},
		{"ASCII で 129 バイト", ascii(129), "id is 129 bytes long; the limit is 128 bytes"},
		{"3 バイトの文字で 128 バイトちょうどに終わる", ascii(125) + "あ", ""},
		{"3 バイトの文字で 128 バイトの境目をまたぐ", ascii(126) + "あ", "id is 129 bytes long"},
		{"4 バイトの文字で 128 バイトの境目をまたぐ", ascii(125) + "🎮", "id is 129 bytes long"},
		{"43 文字で 129 バイト", strings.Repeat("あ", 43), "id is 129 bytes long"},
		{"42 文字で 126 バイト", strings.Repeat("あ", 42), ""},
		{"日本語と ASCII の空白", "週末 サーバ 2456", ""},
		{"記号と絵文字", "game:valley/#1 <a&b> 🎮", ""},
		{"省略記号で終わる", "r_01J…", ""},
		{"不正な UTF-8", "r_\xff", "id is not valid UTF-8"},
		{"途中で切れた UTF-8", "r_\xe3\x81", "id is not valid UTF-8"},
		{"改行", "r_a\nr_b", "id contains U+000A at byte 3"},
		{"復帰", "r_a\r", "U+000D"},
		{"タブ", "r\ta", "U+0009"},
		{"ESC", "r_\x1b[31m", "U+001B"},
		{"DEL", "r_\x7f", "U+007F"},
		{"C1 の NEL", "r_\u0085", "U+0085"},
		{"C1 の CSI", "r_\u009b", "U+009B"},
		{"双方向の上書き", "r_\u202e", "U+202E"},
		{"ゼロ幅接合子", "r_\u200d", "U+200D"},
		{"BOM", "\ufeffr_a", "U+FEFF at byte 0"},
		{"行区切り", "r_\u2028", "U+2028"},
		{"段落区切り", "r_\u2029", "U+2029"},
		{"縦タブ", "r_\va", "U+000B"},
		{"改ページ", "r_\fa", "U+000C"},
		{"全角スペース", "週末\u3000サーバ", ""},
		{"ノーブレークスペース", "r_\u00a0a", ""},
		{"EN QUAD", "r_\u2000a", ""},
		{"空白だけ", " ", ""},
		{"前後の空白", " r_a\u3000", ""},
		{"私用領域", "r_\ue000", "U+E000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := validRule()
			r.ID = tt.id
			err := r.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() with id %q (%d bytes) = %v, want nil", tt.id, len(tt.id), err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() with id %q = %v, want error containing %q", tt.id, err, tt.wantErr)
			}
			// エラーは ID の中身を繰り返さない。制御文字を含む ID がエラーの行を偽らないため
			if strings.ContainsFunc(err.Error(), func(r rune) bool { return r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) }) ||
				!utf8.ValidString(err.Error()) {
				t.Errorf("error %q carries a control character or invalid UTF-8", err)
			}
		})
	}
}

// TestValidateUpsertKeepsStoredRuleIDs は、ID の検査の前に保存された、長すぎるか表示できない
// 文字を含む ID の行の扱いを確かめる(仕様 5.4 節)。触らない限り無関係なバッチを妨げず、書き出しを
// そのまま戻すバッチも通る。同じ ID のまま変えるバッチは拒み、削除と、正しい ID への置き換えは通る。
// 変異の確認:ValidateUpsert が変わらない行の検査を飛ばさないようにすると、無関係なバッチが落ちる。
func TestValidateUpsertKeepsStoredRuleIDs(t *testing.T) {
	for _, id := range []string{strings.Repeat("x", 200), "r_a\nr_b", "r_a\tb", "r_\u2029", "r_\u202e"} {
		legacy := validRule()
		legacy.ID, legacy.ListenPort, legacy.Target = id, PortRange{3000, 3000}, "192.168.1.20:3000"
		other := validRule()
		other.ID = "r_other"
		if legacy.Validate() == nil {
			t.Fatalf("id %q unexpectedly passes Validate(); fix the fixture", id)
		}
		before := []Rule{legacy, other}

		changedOther := other
		changedOther.Enabled = false
		if err := ValidateUpsert([]Rule{legacy, changedOther}, before, nil); err != nil {
			t.Errorf("id %q: an unrelated batch must not fail: %v", id, err)
		}
		added := validRule()
		added.ID, added.ListenPort = "r_new", PortRange{4000, 4000}
		if err := ValidateUpsert([]Rule{legacy, other, added}, before, nil); err != nil {
			t.Errorf("id %q: adding an unrelated rule must not fail: %v", id, err)
		}
		if err := ValidateUpsert([]Rule{legacy, other}, before, nil); err != nil {
			t.Errorf("id %q: re-importing the stored set unchanged must not fail: %v", id, err)
		}
		changedLegacy := legacy
		changedLegacy.Enabled = false
		if err := ValidateUpsert([]Rule{changedLegacy, other}, before, nil); err == nil || !strings.Contains(err.Error(), "id ") {
			t.Errorf("id %q: changing the row while keeping its id = %v, want it refused", id, err)
		}
		if err := ValidateUpsert([]Rule{other}, before, nil); err != nil {
			t.Errorf("id %q: deleting the row must not fail: %v", id, err)
		}
		fixed := legacy
		fixed.ID = "r_fixed"
		if err := ValidateUpsert([]Rule{fixed, other}, before, nil); err != nil {
			t.Errorf("id %q: replacing the row with a valid id on the same port must not fail: %v", id, err)
		}
	}
}
