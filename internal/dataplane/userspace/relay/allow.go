package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"

	"github.com/rahanahu/wgft/internal/reasontext"
)

// targetLookupTimeout は、許可一覧があるときに中継が自分で行う target の名前解決の期限。
const targetLookupTimeout = 5 * time.Second

// ErrTargetNotAllowed は、エージェントが宛先を拒んだこと、つまり宛先が許可一覧の外にあるか、
// ブロードキャストかマルチキャストのアドレスであること(設計文書 7 節)。
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
	return fmt.Sprintf("target %s "+reasontext.NotAllowed, e.target)
}

func (e *notAllowedError) Unwrap() error { return ErrTargetNotAllowed }

// refusedTargetError は、Options.RefuseTarget が拒んだ 1 つの宛先。理由は RefuseTarget の文言そのもの
// である。許可一覧による拒否と同じ扱いにするため、ErrTargetNotAllowed を包む。
type refusedTargetError struct{ reason string }

func (e *refusedTargetError) Error() string { return e.reason }

func (e *refusedTargetError) Unwrap() error { return ErrTargetNotAllowed }

// checksTargets は、中継が宛先を判定するかどうかである。
func (m *Manager) checksTargets() bool {
	return m.opts.AllowTarget != nil || m.opts.RefuseTarget != nil
}

// targetErr は、宛先 ap へ接続しない理由を返す。接続してよければ nil を返す。ブロードキャストと
// マルチキャストの拒否を許可一覧より先に見る。許可一覧に加えても通らない宛先だからである。
func (m *Manager) targetErr(ap netip.AddrPort) error {
	ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	if m.opts.RefuseTarget != nil {
		if r := m.opts.RefuseTarget(ap.Addr()); r != "" {
			return &refusedTargetError{reason: r}
		}
	}
	if m.opts.AllowTarget != nil && !m.opts.AllowTarget(ap) {
		return &notAllowedError{target: ap, source: m.opts.AllowTargetSource}
	}
	return nil
}

// allowedAtApply は、適用のときに宛先を許可一覧とブロードキャストとマルチキャストの拒否に照らす
// (設計文書 7 節の早い通知)。判定できるのは IP リテラルの宛先だけで、ホスト名は解決の結果が
// 変わりうるので接続のときに照らす。
func (m *Manager) allowedAtApply(target string) error {
	if !m.checksTargets() {
		return nil
	}
	ap, err := netip.ParseAddrPort(target)
	if err != nil {
		return nil // ホスト名
	}
	return m.targetErr(ap)
}

// dialTarget は宛先へ接続する。中継が宛先へ接続する唯一の経路なので、宛先の判定もここに置く。
// 許可一覧があるときは、実際に接続するアドレスで判定するために自分で名前解決し、許したアドレスだけに
// dialAddrs で接続する。許可一覧が無いときは dialByName を使う。
func (m *Manager) dialTarget(network, target string) (net.Conn, error) {
	if m.opts.AllowTarget == nil {
		return m.dialByName(network, target)
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
	var denied error
	allowed := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		a = a.Unmap()
		if err := m.targetErr(netip.AddrPortFrom(a, uint16(n))); err != nil {
			if denied == nil {
				denied = err
			}
			continue
		}
		allowed = append(allowed, a)
	}
	switch {
	case len(allowed) > 0:
		return m.dialAddrs(network, portStr, allowed)
	case denied != nil:
		return nil, denied
	default:
		return nil, fmt.Errorf("target %q resolved to no address", target)
	}
}

// dialAddrs は、許可一覧が通したアドレスへ接続する(設計文書 7 節)。試し方は、許可一覧が無いときに
// 名前を渡す net.Dialer に合わせる。TCP では先頭のアドレスと同じ族のアドレスを先に試し、
// targetFallbackDelay のうちに繋がらなければ、もう一方の族のアドレスも並行して試し始める。それぞれの族の
// 中では順に試し、期限 dialTimeout の残りをまだ試していないアドレスで分ける(dialSerial)。UDP は
// net.Dialer と同じく族を分けない。先に繋がった接続を返し、後から繋がった接続は閉じる。
//
// net.Dialer そのものに判定を任せる形(Control で判定する)は採らない。名前の解決が Go の接続の中に
// 移り、すべて失敗したときに返る誤りが、通したアドレスの接続の失敗ではなく先頭のアドレスの拒否に
// なりうるからである。
//
// すべて失敗した場合は、解決の結果の順で最後に試したアドレスの誤りを返す。この試し方の前に、
// アドレスを順に 1 つずつ試していたときと同じ選び方である。
func (m *Manager) dialAddrs(network, port string, addrs []netip.Addr) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m.dialTimeout)
	defer cancel()
	errs := make([]error, len(addrs))
	idx := make([]int, len(addrs))
	for i := range idx {
		idx[i] = i
	}
	var primaries, fallbacks []int
	if network == "tcp" {
		for _, i := range idx {
			if addrs[i].Is4() == addrs[0].Is4() {
				primaries = append(primaries, i)
			} else {
				fallbacks = append(fallbacks, i)
			}
		}
	} else {
		primaries = idx
	}
	if len(fallbacks) == 0 {
		if c := m.dialSerial(ctx, network, port, addrs, primaries, errs); c != nil {
			return c, nil
		}
		return nil, lastErr(errs)
	}

	// 2 つの族を競わせる。結果を受け取らなくなった後に繋がった接続は、試した側が閉じる
	returned := make(chan struct{})
	defer close(returned)
	results := make(chan net.Conn) // 失敗は nil。誤りは errs に書く
	race := func(ctx context.Context, list []int) {
		c := m.dialSerial(ctx, network, port, addrs, list, errs)
		select {
		case results <- c:
		case <-returned:
			if c != nil {
				c.Close()
			}
		}
	}
	primaryCtx, cancelPrimary := context.WithCancel(ctx)
	defer cancelPrimary()
	fallbackCtx, cancelFallback := context.WithCancel(ctx)
	defer cancelFallback()
	go race(primaryCtx, primaries)
	fallback := time.NewTimer(targetFallbackDelay)
	defer fallback.Stop()
	started, done := 1, 0
	for {
		select {
		case <-fallback.C:
			started++
			go race(fallbackCtx, fallbacks)
		case c := <-results:
			if c != nil {
				return c, nil
			}
			done++
			if done == 2 {
				// errs は両方の競争相手が書き終え、results の受け取りで見える
				return nil, lastErr(errs)
			}
			if started == 1 && fallback.Stop() {
				// 先の族がすべて失敗した。待たずにもう一方の族を試す
				fallback.Reset(0)
			}
		}
	}
}

// dialSerial は、addrs のうち list の位置のアドレスを順に試し、最初に繋がった接続を返す。すべて
// 失敗すれば nil を返す。失敗した位置の誤りは errs に書く。各アドレスには、ctx の期限の残りを
// まだ試していないアドレスの数で分けた期限を与え、ただし 2 秒を下回らせない(net.Dialer と同じ分け方)。
func (m *Manager) dialSerial(ctx context.Context, network, port string, addrs []netip.Addr, list []int, errs []error) net.Conn {
	for k, i := range list {
		if ctx.Err() != nil {
			return nil
		}
		dctx, cancel := ctx, context.CancelFunc(func() {})
		if dl, ok := ctx.Deadline(); ok {
			dctx, cancel = context.WithDeadline(ctx, addrDeadline(time.Now(), dl, len(list)-k))
		}
		c, err := m.dialCtx(dctx, network, net.JoinHostPort(addrs[i].String(), port))
		cancel()
		if err == nil {
			return c
		}
		errs[i] = err
	}
	return nil
}

// minAddrDialTimeout は、許可一覧があるときに 1 つのアドレスへ与える期限の下限(net.Dialer と同じ値)。
const minAddrDialTimeout = 2 * time.Second

// addrDeadline は、残り remaining 個のアドレスを試すときの、次の 1 つの期限を返す。
func addrDeadline(now, deadline time.Time, remaining int) time.Time {
	left := deadline.Sub(now)
	per := left / time.Duration(remaining)
	if per < minAddrDialTimeout {
		per = min(left, minAddrDialTimeout)
	}
	return now.Add(per)
}

// lastErr は、解決の結果の順で最後に試したアドレスの誤りを返す。どのアドレスも試す前に期限が
// 来た場合は、期限切れの誤りを返す。
func lastErr(errs []error) error {
	for i := len(errs) - 1; i >= 0; i-- {
		if errs[i] != nil {
			return errs[i]
		}
	}
	return fmt.Errorf("dial: %w", context.DeadlineExceeded)
}

// dialByName は許可一覧が無いときの経路であり、宛先を名前のまま Options.Dial に渡す。名前の解決、
// 2 つのアドレスの族を少しずらして試すこと、期限をアドレスの間で分けることを Go の接続に任せ、
// ブロードキャストとマルチキャストの拒否の導入の前と同じ挙動に保つためである。拒否は、既定の Dial の
// Control(refuseControl)が、解決した各アドレスへ接続する前に当てる。拒む IP リテラルの宛先は、
// 適用のときに待ち受けを開かないので(allowedAtApply)、ここへは来ない。拒んだアドレスは飛ばされ、Go の接続は次のアドレスを試す。拒否で終わった接続の誤りは、
// 理由の文言を 2 つのモードでそろえるため、Go の接続の文言で包まずに返す(設計文書 7 節)。
func (m *Manager) dialByName(network, target string) (net.Conn, error) {
	c, err := m.opts.Dial(network, target)
	var refused *refusedTargetError
	if err != nil && errors.As(err, &refused) {
		return nil, refused
	}
	return c, err
}

// refuseControl は、既定の Dial の net.Dialer に置く Control である。Go の接続が名前を解決した後、
// アドレスごとにソケットを作ってから接続する前に呼ばれるので、実際に接続するアドレスを refuse で判定できる。
// 拒めば接続せず、Go の接続は次のアドレスへ進む。
func refuseControl(refuse func(netip.Addr) string) func(ctx context.Context, network, address string, c syscall.RawConn) error {
	return func(_ context.Context, _, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return nil
		}
		if r := refuse(ap.Addr().Unmap()); r != "" {
			return &refusedTargetError{reason: r}
		}
		return nil
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

// noteTargetAllowErr は、接続のときの宛先の拒否をリスナーの状態に載せる(設計文書 5.2 節)。
// 扱うのは許可一覧と、ブロードキャストとマルチキャストの拒否だけで、宛先が落ちているなどの接続の
// 失敗は今までどおりログだけにする。err が nil なら、前に載せた拒否を消す(DNS が許す宛先に戻った場合)。
//
// 接続 1 本ごと、UDP のセッション 1 つごとに呼ばれるので、状態が変わらない限り Manager の錠を取らない。
// 宛先を判定しなければ何もせず、判定しても、拒否が続く間と通り続ける間は allowDenied の読みだけで返る。
func (m *Manager) noteTargetAllowErr(l *listener, err error) {
	if !m.checksTargets() {
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
