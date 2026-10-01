package agent

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/startup"
)

// recover は stream の認証が拒否(401)されたときの復帰経路(仕様 5.1 節)。
// WGFT_JOIN があり、使用済みでなければ初回登録をやり直す。認証情報ファイルは登録が成功した時点で置き換え、
// 失敗したら既存のファイルを残したまま止まる(期限切れのトークンで鍵まで失わないため)。
// この 3 つの分岐は、ensureRegistered の同じ 3 つと同じ理由で拒否として返す。稼働中に起きても、
// 直すには運用者が新しい接続文字列を発行するしかなく、再起動の繰り返しでは直らない(設計文書 11b 節)。
func (rt *runtime) recover() error {
	if rt.opts.Join == "" {
		return startup.Config("WGFT_JOIN", "permanent token was revoked; provide a new join string via WGFT_JOIN and restart")
	}
	j, err := ParseJoin(rt.opts.Join)
	if err != nil {
		return startup.Config("WGFT_JOIN", "%v", err)
	}
	if j.TokenHash() == rt.f.UsedJoinTokenSHA256 {
		return startup.Conflict("WGFT_JOIN", "permanent token was revoked and the local join string is already used; issue a new join string and replace WGFT_JOIN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tok, addr, name, err := Register(ctx, j, rt.opts.Name)
	if err != nil {
		return fmt.Errorf("re-register failed: %w", err)
	}
	rt.mu.Lock()
	// 登録のし直しは、記録したトンネルのアドレスを置き換える唯一の経路である(設計文書 9・11 節)
	recordRegistration(rt.f, j, tok, addr, name)
	err = rt.f.Save(rt.opts.CredentialsPath)
	rt.mu.Unlock()
	if err != nil {
		return err
	}
	log.Printf("re-registered as agent %s; assigned %s", name, addr)
	return nil
}

// joinForNewPin は、ピンの不一致からの再登録に使える接続文字列を返す(仕様 5.1 節)。
// 未使用で、かつピンが認証情報のピンと違うものだけ。なければ nil。
func (rt *runtime) joinForNewPin() *Join {
	if rt.opts.Join == "" {
		return nil
	}
	j, err := ParseJoin(rt.opts.Join)
	if err != nil {
		return nil
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if j.TokenHash() == rt.f.UsedJoinTokenSHA256 || hex.EncodeToString(j.Pin[:]) == rt.f.CertSHA256 {
		return nil
	}
	return j
}

// ensureRegistered は初回登録を行う(仕様 5.1 節)。恒久トークンがあれば何もしない。
// WGFT_JOIN が compose に残ったまま再起動されるのが普通なので、使用済みの接続文字列は黙って無視する。
// WGFT_NAME / --name は任意。接続文字列の発行時の名前に紐付いているので、与えなければトークンに
// 紐付いた名前で登録される。与えて既に登録済みの名前と違えば警告して登録済みの名前を使う。
func ensureRegistered(f *credentials.Credentials, opts Options) error {
	if f.PermanentToken != "" {
		if opts.Name != "" && opts.Name != f.Name {
			log.Printf("WGFT_NAME=%s differs from the registered name %s; keeping %s", opts.Name, f.Name, f.Name)
		}
		if opts.Join != "" {
			if j, err := ParseJoin(opts.Join); err == nil && j.TokenHash() != f.UsedJoinTokenSHA256 {
				log.Printf("already registered; ignoring the provided join string and using the existing permanent token")
			}
		}
		return nil
	}
	// この 3 つはどれも再試行では直らない。cmd/wgft は *startup.Refusal を終了コード 3 に写すので、
	// 同梱の agent.service の RestartPreventExitStatus=3 が 2 秒おきの再起動を止める。値だけから
	// 判定できる 2 つ目(構文)を入口ではなく登録の直前で判定するのは、登録済みの agent では
	// compose に残った古い WGFT_JOIN を読まないためである(設計文書 11a・11b 節)。
	if opts.Join == "" {
		return startup.Config("WGFT_JOIN", "not registered and no join string; provide via WGFT_JOIN or --join")
	}
	j, err := ParseJoin(opts.Join)
	if err != nil {
		return startup.Config("WGFT_JOIN", "%v", err)
	}
	if j.TokenHash() == f.UsedJoinTokenSHA256 {
		return startup.Conflict("WGFT_JOIN", "this join string is already used; issue a new join string")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tok, addr, name, err := Register(ctx, j, opts.Name)
	if err != nil {
		return err
	}
	// 登録が成功した時点で認証情報ファイルを置き換える(失敗したら既存のファイルはそのまま)
	recordRegistration(f, j, tok, addr, name)
	if err := f.Save(opts.CredentialsPath); err != nil {
		return err
	}
	log.Printf("registered as agent %s; assigned %s, API %s", name, addr, j.Endpoint)
	return nil
}

// recordRegistration は登録の結果を認証情報に写す。初回の登録(ensureRegistered)と登録のし直し
// (recover)が共有する。排他は取らない。recover は rt.mu を持ったまま呼び、保存も呼び出し側が行う。
func recordRegistration(f *credentials.Credentials, j *Join, tok, addr, name string) {
	f.Name, f.Endpoint, f.PermanentToken = name, j.Endpoint, tok
	f.CertSHA256 = hex.EncodeToString(j.Pin[:])
	f.UsedJoinTokenSHA256 = j.TokenHash()
	f.TunnelAddress = credentials.RegisteredTunnelAddress(addr)
}
