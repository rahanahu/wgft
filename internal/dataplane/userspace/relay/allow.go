package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// targetLookupTimeout は、許可一覧があるときに中継が自分で行う target の名前解決の期限。
const targetLookupTimeout = 5 * time.Second

// ErrTargetNotAllowed は、宛先が許可一覧の外にあること(設計文書 7 節)。
// 呼び出し側は errors.Is でこの誤りを見分け、他の接続の失敗と区別できる。
var ErrTargetNotAllowed = errors.New("target is not allowed")

// notAllowedError は許可一覧が拒んだ 1 つの宛先。理由には設定の名前を含める。
type notAllowedError struct {
	target netip.AddrPort
	source string
}

func (e *notAllowedError) Error() string {
	if e.source != "" {
		return fmt.Sprintf("target %s is not in %s", e.target, e.source)
	}
	return fmt.Sprintf("target %s is not allowed", e.target)
}

func (e *notAllowedError) Unwrap() error { return ErrTargetNotAllowed }

// allowedAtApply は、適用のときに宛先を許可一覧と照らす(設計文書 7 節の早い通知)。
// 判定できるのは IP リテラルの宛先だけで、ホスト名は解決の結果が変わりうるので接続のときに照らす。
func (m *Manager) allowedAtApply(target string) error {
	if m.opts.AllowTarget == nil {
		return nil
	}
	ap, err := netip.ParseAddrPort(target)
	if err != nil {
		return nil // ホスト名
	}
	ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	if m.opts.AllowTarget(ap) {
		return nil
	}
	return &notAllowedError{target: ap, source: m.opts.AllowTargetSource}
}

// dialTarget は宛先へ接続する。中継が宛先へ接続する唯一の経路なので、許可一覧の判定もここに置く。
// 許可一覧があるときは、実際に接続するアドレスで判定するために自分で名前解決し、許したアドレスだけに接続する。
func (m *Manager) dialTarget(network, target string) (net.Conn, error) {
	if m.opts.AllowTarget == nil {
		return m.opts.Dial(network, target)
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("target %q is not in host:port form", target)
	}
	n, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || n == 0 {
		return nil, fmt.Errorf("target %q port is not an integer in 1-65535", target)
	}
	addrs, err := m.lookupTarget(host)
	if err != nil {
		return nil, err
	}
	var denied, dialErr error
	for _, a := range addrs {
		a = a.Unmap()
		if !m.opts.AllowTarget(netip.AddrPortFrom(a, uint16(n))) {
			if denied == nil {
				denied = &notAllowedError{target: netip.AddrPortFrom(a, uint16(n)), source: m.opts.AllowTargetSource}
			}
			continue
		}
		c, err := m.opts.Dial(network, net.JoinHostPort(a.String(), portStr))
		if err == nil {
			return c, nil
		}
		dialErr = err
	}
	switch {
	case dialErr != nil:
		return nil, dialErr
	case denied != nil:
		return nil, denied
	default:
		return nil, fmt.Errorf("target %q resolved to no address", target)
	}
}

// lookupTarget は宛先のホストを解決する。IP リテラルはそのまま返す。
func (m *Manager) lookupTarget(host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a.Unmap()}, nil
	}
	lookup := m.opts.LookupTarget
	if lookup == nil {
		lookup = func(ctx context.Context, h string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", h)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), targetLookupTimeout)
	defer cancel()
	addrs, err := lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("host %q resolved to no address", host)
	}
	return addrs, nil
}

// noteTargetAllowErr は、接続のときの許可一覧による拒否をリスナーの状態に載せる(設計文書 5.2 節)。
// 扱うのは許可一覧による拒否だけで、宛先が落ちているなどの接続の失敗は今までどおりログだけにする。
// err が nil なら、前に載せた拒否を消す(DNS が許す宛先に戻った場合)。
//
// 接続 1 本ごと、UDP のセッション 1 つごとに呼ばれるので、状態が変わらない限り Manager の錠を取らない。
// 許可一覧が無ければ何もせず、一覧があっても、拒否が続く間と通り続ける間は allowDenied の読みだけで返る。
func (m *Manager) noteTargetAllowErr(l *listener, err error) {
	if m.opts.AllowTarget == nil {
		return
	}
	denied := err != nil && errors.Is(err, ErrTargetNotAllowed)
	if err != nil && !denied {
		return
	}
	if denied == l.allowDenied.Load() {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if denied {
		setTargetErrLocked(l, err)
		return
	}
	// 許可に戻った。許可一覧による拒否だけを消し、他の理由は残す
	if l.targetErr != nil && errors.Is(l.targetErr, ErrTargetNotAllowed) {
		setTargetErrLocked(l, nil)
		return
	}
	l.allowDenied.Store(false)
}

// setTargetErrLocked は宛先の状態を書き、許可一覧による拒否かどうかの印を合わせる(m.mu を持って呼ぶ)。
// 印は noteTargetAllowErr が錠を取らずに状態の変化を見分けるためにあるので、targetErr を書く場所は
// すべてこの関数を通す。
func setTargetErrLocked(l *listener, err error) {
	l.targetErr = err
	l.allowDenied.Store(err != nil && errors.Is(err, ErrTargetNotAllowed))
}
