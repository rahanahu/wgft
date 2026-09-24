package admin

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/doctor"
	"github.com/rahanahu/wgft/proto"
)

// 宛先の節点の 2 つ目の注記(設計文書 10.2a 節「UDP の応答の観測」)。server 自身が見た応答の
// 観測を、状態の色を持たない控えめな注記として添え、代替テキストにも入れる。節点の状態と語は
// 観測によって変わらない。観測できないことは、未観測と別の文で示す。
func TestDoctorPathUDPReplyNote(t *testing.T) {
	udp := pathRule("r_udp", proto.UDP)
	cases := []struct {
		name string
		obs  map[string]UDPReply
		want string
	}{
		{"no report", nil, ""},
		{"recent reply", map[string]UDPReply{"r_udp": {Since: pathAt(3 * time.Hour), LastReplyAt: pathAt(18 * time.Second)}},
			fmt.Sprintf(T("en", "doctorUDPLastReply"), "18s ago")},
		{"none seen", map[string]UDPReply{"r_udp": {Since: pathAt(3 * time.Hour)}},
			fmt.Sprintf(T("en", "doctorUDPNoReply"), "3h ago")},
		{"not observed", map[string]UDPReply{"r_udp": {NotObserved: "reading the reply counters: permission denied"}},
			fmt.Sprintf(T("en", "doctorUDPNotObserved"), "reading the reply counters: permission denied")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, paths := buildPath(t, pathCase{tc.name, []proto.Rule{udp}, func(in *doctor.Input) { in.Rules.UDPReplies = tc.obs }})
			n := paths[0].Nodes[3]
			if n.ReplyNote != tc.want {
				t.Errorf("reply note = %q, want %q", n.ReplyNote, tc.want)
			}
			if n.Word != "NOT TESTED" || n.State != nodeUntested || n.Note != T("en", "doctorUDPTargetNote") {
				t.Errorf("the observation changed the node: %q %q %q", n.Word, n.State, n.Note)
			}
			if tc.want != "" && !strings.Contains(n.Alt, tc.want) {
				t.Errorf("the alt lacks the reply note: %q", n.Alt)
			}
		})
	}
}

// 2 つ目の注記は日英の両方で作る。
func TestDoctorReplyNoteInBothLocales(t *testing.T) {
	udp := pathRule("r_udp", proto.UDP)
	in := pathInput(udp)
	in.Rules.UDPReplies = map[string]UDPReply{"r_udp": {Since: pathAt(3 * time.Hour)}}
	rep := doctor.BuildReport([]proto.Rule{udp}, in)
	for _, lang := range []string{"ja", "en"} {
		p := doctorPath(rep.Rules[0], rep.ChecksOf("r_udp"), in.Now, lang)
		want := fmt.Sprintf(T(lang, "doctorUDPNoReply"), agoDur(3*time.Hour, lang))
		if got := p.Nodes[3].ReplyNote; got != want {
			t.Errorf("%s: reply note = %q, want %q", lang, got, want)
		}
	}
}
