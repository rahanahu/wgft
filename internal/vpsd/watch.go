//go:build linux

package vpsd

import (
	"context"
	"fmt"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"log"
	"net/netip"
	"sync"
	"time"
)

// watchIPMismatch は 15 秒ごとに、生きている stream の接続元 IP と、最近ハンドシェイクした
// wg エンドポイント IP を比べ、食い違いが 2 分(連続 8 回)続いたら ip-mismatch を 1 件残す
// (仕様 5.2 節)。自宅回線の IP 更新では、旧 stream が死んで新 stream と wg が同じ IP に揃うので
// 警告しない。置き換えそのものは検知しない。
func (d *Daemon) watchIPMismatch(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	counts := map[string]int{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		d.ipMismatchTick(counts)
	}
}

// ipMismatchTick is one 15-second observation, split out of watchIPMismatch so it can be
// unit-tested directly (the ticker itself is not injectable, and this package has no netlink
// test double to drive a real 15-second wait). counts is mutated in place, matching the loop's
// state carried across ticks.
func (d *Daemon) ipMismatchTick(counts map[string]int) {
	dev, err := d.dp.WGStatus()
	if err != nil {
		// この回の判定を飛ばす(design.md 5.2・10.5 節のフェイルオープン)。原因はログに
		// 残し、持続する失敗が journal から見えるようにする(15 秒間隔なので、要求の
		// たびに増える種類のログではない)。
		log.Printf("ip mismatch watch: reading wg status: %v", err)
		return
	}
	now := time.Now()
	endpoint := map[string]string{} // pubkey → 最近(3 分以内)ハンドシェイクしたエンドポイント IP
	for _, p := range dev.Peers {
		if p.Endpoint == nil || p.LastHandshakeTime.IsZero() || now.Sub(p.LastHandshakeTime) > 3*time.Minute {
			continue
		}
		if ip, ok := netip.AddrFromSlice(p.Endpoint.IP); ok {
			endpoint[p.PublicKey.String()] = ip.Unmap().String()
		}
	}
	list, err := d.st.Agents()
	if err != nil {
		log.Printf("ip mismatch watch: reading agents: %v", err)
		return
	}
	for _, a := range list {
		streamIP := ""
		st := d.hub.Status(a.Name)
		if st.Connected && !st.LastHeartbeat.IsZero() && now.Sub(st.LastHeartbeat) <= 45*time.Second {
			streamIP = st.StreamFrom
		}
		wgIP := ""
		if a.PublicKey != "" {
			wgIP = endpoint[a.PublicKey]
		}
		// 第 2 判定:wg エンドポイント IP の往復。stream 側は hub の接続事象で記録する(仕様 5.2 節)
		d.observeFlap(a.Name, "wg", "wg endpoint", wgIP)
		n, warn := ipMismatchStep(counts[a.Name], streamIP, wgIP)
		counts[a.Name] = n
		if warn {
			detail := fmt.Sprintf("stream %s / wg %s", streamIP, wgIP)
			if err := d.st.AddWarning(a.Name, store.WarnIPMismatch, detail); err == nil {
				log.Printf("agent %s: detected IP mismatch: %s", a.Name, detail)
			}
		}
	}
}

// ipMismatchStep は 1 回の観測。両 IP が観測でき食い違っていれば連続回数を増やし、8 回で警告。
// どちらか観測できない、または一致していれば 0 に戻す(警告は消さない、仕様 5.2 節)。
func ipMismatchStep(count int, streamIP, wgIP string) (int, bool) {
	if streamIP == "" || wgIP == "" || streamIP == wgIP {
		return 0, false
	}
	count++
	return count, count >= 8
}

// flapWindow は「以前の値へ戻った」とみなす時間区間(仕様 5.2 節)。
const flapWindow = 10 * time.Minute

// ipObs は 1 チャネルで観測した 1 つの IP と、その最終観測時刻。
type ipObs struct {
	IP string
	At time.Time
}

// flapState はエージェントごと・チャネル(stream / wg)ごとの直近の IP 変化を持つ。
// stream の接続事象(hub の goroutine)と wg の 15 秒ティックから触られるので mu で守る。
type flapState struct {
	mu   sync.Mutex
	hist map[string]map[string][]ipObs // agent -> channel -> 履歴
}

// flapStep は履歴に now 時点の ip を足し、それが「直前の値ではなく、それより前に区間内で
// 持っていた値」に一致すれば往復(flapped=true)とする純関数。区間を超えた古い項目は落とす。
// 同じ IP が続くときは最終観測時刻を更新するだけで往復にはしない(仕様 5.2 節)。
func flapStep(hist []ipObs, ip string, now time.Time, window time.Duration) (out []ipObs, flapped bool, other string) {
	for _, e := range hist {
		if now.Sub(e.At) <= window {
			out = append(out, e)
		}
	}
	if len(out) > 0 && out[len(out)-1].IP == ip {
		out[len(out)-1].At = now
		return out, false, ""
	}
	if len(out) > 0 {
		other = out[len(out)-1].IP
	}
	for _, e := range out {
		if e.IP == ip {
			flapped = true
			break
		}
	}
	out = append(out, ipObs{IP: ip, At: now})
	if len(out) > 8 {
		out = out[len(out)-8:]
	}
	return out, flapped, other
}

// observeFlap は 1 チャネルの IP を 1 つ観測し、往復していれば ip-flapping 警告を残す。
// ip が空(観測できない)ときは何もしない。
func (d *Daemon) observeFlap(agent, channel, label, ip string) {
	if ip == "" {
		return
	}
	d.flaps.mu.Lock()
	if d.flaps.hist[agent] == nil {
		d.flaps.hist[agent] = map[string][]ipObs{}
	}
	out, flapped, other := flapStep(d.flaps.hist[agent][channel], ip, time.Now(), flapWindow)
	d.flaps.hist[agent][channel] = out
	d.flaps.mu.Unlock()
	if !flapped {
		return
	}
	a, b := ip, other
	if a > b {
		a, b = b, a
	}
	detail := fmt.Sprintf("%s alternated between %s and %s", label, a, b)
	if err := d.st.AddWarning(agent, store.WarnIPFlapping, detail); err == nil {
		log.Printf("agent %s: detected IP flapping: %s", agent, detail)
	}
}
