//go:build linux

package vpsd

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/rahanahu/wgft/internal/platform/linux"
	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// DisableAgent は admin.Backend の実装。エージェントを無効にする(仕様 5.1 節)。
//
// 順序は、保存の確定、接続中の全エージェントへの配信、dataplane への公開である。配信は公開の成否を
// 待たない。止める向きの配信は公開より先に届いても安全側だからである。ルールのバッチは公開に失敗すると
// 配らないが、無効化だけがこの点で例外になる。公開に失敗したら、保存は済んでいるので
// *admin.AgentChangeError(Saved が真)を返す。30 秒ごとの再試行(retryOnce)が公開する。
//
// 既に無効なら、何も保存せず、配らず、公開もせず、Changed を偽にして成功を返す(仕様 7a.11 節)。
// 前の無効化が公開に失敗したままなら、その公開は 30 秒ごとの再試行が行う。
func (d *Daemon) DisableAgent(name string) (admin.AgentDisabledResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.st.SetAgentDisabled(name, true, time.Now(), nil)
	if err != nil {
		if errors.Is(err, store.ErrAgentNotFound) {
			return admin.AgentDisabledResponse{}, err
		}
		return admin.AgentDisabledResponse{}, fmt.Errorf("saving agent %s as disabled: %w", name, err)
	}
	out := admin.AgentDisabledResponse{Name: name, Disabled: true, Changed: res.Changed, Generation: res.Generation}
	if !res.Changed {
		return out, nil
	}
	d.lag.serverAt(res.Generation, time.Now())
	log.Printf("disabled agent %s at generation %d", name, res.Generation)
	d.pushedAhead = res.Generation
	d.pushAll()
	if err := d.applyNFT(res.Rules); err != nil {
		log.Printf("agent %s: disable saved, but applying the data plane failed: %v", name, err)
		return out, &admin.AgentChangeError{Saved: true, Err: fmt.Errorf(
			"saved: agent %s is disabled in the server database, but the change is not published yet: %w; the server retries every 30s", name, err)}
	}
	return out, nil
}

// EnableAgent は admin.Backend の実装。エージェントを有効に戻す(仕様 5.1 節)。
//
// 有効化は、そのエージェントの有効なルールに、ルールのバッチの upsert と同じ書き込みの時の検査
// (他のテーブルの DNAT との重なりと、VPS 上で bind 中のポート)を行う。force の上書きは持たない。
// 検査が拒んだら何も保存せず、*admin.AgentChangeError(Saved が偽)を返す。検査のための読み取りの
// 失敗は拒否ではないので、ふつうの誤り(500)にする。
//
// 順序は、保存の確定、dataplane への公開、公開が成功したときだけ配信である。配信は、公開した世代が
// 進んだときに apply が行う。公開に失敗したら配らず、*admin.AgentChangeError(Saved が真)を返す。
// その世代を後から公開した経路(30 秒ごとの再試行や、別のバッチ)で apply が配る。公開に失敗して
// いる間、VPS とエージェントの両方が止まったままなので安全側である。
//
// 既に有効なら、検査も保存も配信も公開もせず、Changed を偽にして成功を返す(仕様 7a.11 節)。
func (d *Daemon) EnableAgent(name string) (admin.AgentDisabledResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	// 状態を先に読み、無効なときだけ検査のための読み取りをする。d.mu の下なので、この間に他の経路が
	// 無効と有効の状態やルールを変えることはない(どちらの書き込みも d.mu を取る)
	cur, err := d.st.AgentByName(name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return admin.AgentDisabledResponse{}, &store.AgentNotFoundError{Name: name}
		}
		return admin.AgentDisabledResponse{}, fmt.Errorf("reading agent %s: %w", name, err)
	}
	var check func([]proto.Rule) error
	var refused error
	if cur.Disabled() {
		rep, err := d.dp.Inspect()
		if err != nil {
			return admin.AgentDisabledResponse{}, fmt.Errorf("inspecting other tables before enabling agent %s: %w", name, err)
		}
		bound, err := d.dp.BoundPorts()
		if err != nil {
			return admin.AgentDisabledResponse{}, fmt.Errorf("checking bound ports before enabling agent %s: %w", name, err)
		}
		check = func(rules []proto.Rule) error {
			refused = enableConflict(name, rules, rep, bound)
			return refused
		}
	}
	res, err := d.st.SetAgentDisabled(name, false, time.Now(), check)
	if err != nil {
		switch {
		case refused != nil:
			return admin.AgentDisabledResponse{}, &admin.AgentChangeError{Saved: false, Err: fmt.Errorf(
				"refused to enable agent %s; nothing changed: %w", name, refused)}
		case errors.Is(err, store.ErrAgentNotFound):
			return admin.AgentDisabledResponse{}, err
		}
		return admin.AgentDisabledResponse{}, fmt.Errorf("saving agent %s as enabled: %w", name, err)
	}
	out := admin.AgentDisabledResponse{Name: name, Disabled: false, Changed: res.Changed, Generation: res.Generation}
	if !res.Changed {
		return out, nil
	}
	d.lag.serverAt(res.Generation, time.Now())
	log.Printf("enabled agent %s at generation %d", name, res.Generation)
	if err := d.applyNFT(res.Rules); err != nil {
		log.Printf("agent %s: enable saved, but applying the data plane failed: %v", name, err)
		return out, &admin.AgentChangeError{Saved: true, Err: fmt.Errorf(
			"saved: agent %s is enabled in the server database, but the change is not published yet: %w; the server retries every 30s and delivers the rules to the agent once published", name, err)}
	}
	return out, nil
}

// enableConflict は、有効化するエージェントの有効なルールに、ルールのバッチの upsert と同じ
// 書き込みの時の検査を行う(仕様 5.1 節)。force の上書きは無い。
func enableConflict(agent string, rules []proto.Rule, rep *linux.Report, bound linux.Bound) error {
	for i := range rules {
		if rules[i].Agent != agent {
			continue
		}
		if err := ruleConflict(&rules[i], rep, bound, "risk of locking out SSH etc.; free the port and enable the agent again"); err != nil {
			return err
		}
	}
	return nil
}

// activeGeneration は最後に公開に成功した世代である。まだ一度も適用を試みていなければ 0。
func (d *Daemon) activeGeneration() uint64 {
	if d.rec == nil {
		return 0
	}
	return d.rec.Status().ActiveGeneration
}

// pushAll は接続中の全エージェントへ全体状態を配り直す。配信は待たない。
func (d *Daemon) pushAll() {
	if d.onPushAll != nil {
		d.onPushAll()
		return
	}
	if d.hub != nil {
		go d.hub.PushAll()
	}
}
