package lograte

import (
	"errors"
	"net"
	"regexp"
)

// socketPair は、Go の名前解決の誤りの文面に入る「read udp <送信元>-><DNS サーバ>: 」の部分である。
// 送信元のポートは問い合わせごとに変わる。
var socketPair = regexp.MustCompile(`(?:read|write) (?:udp|tcp)[46]? \S+->\S+: `)

// StableError は、名前の解決の誤りの文面から、問い合わせごとに変わる送信元とサーバのソケットの組を除く。
// 文面の変化で状態の変化を見分ける呼び出し側(ルールの理由、変化のときだけ出すログ)が、同じ誤りを
// 30 秒ごとに新しい誤りとして扱わないためである。DNS サーバは *net.DNSError の文面の "on <サーバ>" に
// 残る。*net.DNSError を含まない誤りと、文面に組を含まない誤りは、そのまま返す。返す誤りは元の誤りを
// Unwrap で返すので、errors.As と errors.Is はそのまま効く。
func StableError(err error) error {
	var dnsErr *net.DNSError
	if err == nil || !errors.As(err, &dnsErr) {
		return err
	}
	msg := err.Error()
	stable := socketPair.ReplaceAllString(msg, "")
	if stable == msg {
		return err
	}
	return &stableError{msg: stable, err: err}
}

type stableError struct {
	msg string
	err error
}

func (e *stableError) Error() string { return e.msg }
func (e *stableError) Unwrap() error { return e.err }
