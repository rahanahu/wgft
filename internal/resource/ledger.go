package resource

import "fmt"

// Ledger は帳簿の読み出し。relay と proxyrelay の試験が帳簿を照合するために使う。
type Ledger struct {
	InUse, Total, RuleCap, Minimum int
	Rules                          int            // N
	Unfilled, FloorShort           int            // S、S_f
	Claim                          int            // 請求の合計 E = u + S + P
	RegFlows                       map[string]int // ルールの今の登録の a_g
	RegCarried                     map[string]int // ルールの今の登録の c_g
	RegSerial                      map[string]int
	RetiredFlows                   int // 退役した登録に残るフロー
	RetiredRegs                    int
	Orphans                        int // 退役した登録にあり、受け付けている listener が運ぶフロー(0 のはず)
	NotAccepting, DoubleReleases   uint64
}

// Ledger は帳簿を複製して返す。
func (p *Pool) Ledger() Ledger {
	p.mu.Lock()
	defer p.mu.Unlock()
	lg := Ledger{
		InUse: p.inUse, Total: p.total, RuleCap: p.ruleCap, Minimum: p.minimum, Rules: len(p.regs),
		Unfilled: p.unfilled, FloorShort: p.floorShort, Claim: p.inUse + p.unfilled + FlowFloor,
		RegFlows: map[string]int{}, RegCarried: map[string]int{}, RegSerial: map[string]int{},
		RetiredRegs: len(p.retired), NotAccepting: p.notAccepting, DoubleReleases: p.doubleReleases,
	}
	for r, g := range p.regs {
		lg.RegFlows[r] = g.count
		lg.RegCarried[r] = g.carried
		lg.RegSerial[r] = g.serial
	}
	for g := range p.retired {
		lg.RetiredFlows += g.count
		for c := range g.cells {
			if c.l.counted {
				lg.Orphans += c.n
			}
		}
	}
	return lg
}

// CheckLedger は足し引きで保った帳簿を、登録と cell の値から作り直した値と照合する。u が cell の和と
// 一致すること、a_g、c_g、m、S、S_f、項が正の登録の数が作り直した値と一致すること、受け付けている
// listener が運ぶフローが退役した登録に無いことを確かめる。
func (p *Pool) CheckLedger() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.total > 0 && p.inUse > p.total {
		return fmt.Errorf("u %d > T %d", p.inUse, p.total)
	}
	all := make([]*registration, 0, len(p.regs)+len(p.retired))
	for r, g := range p.regs {
		if g.retired || g.rule != r || g.members <= 0 {
			return fmt.Errorf("registration %s#%d in A: retired %v, members %d", g.rule, g.serial, g.retired, g.members)
		}
		all = append(all, g)
	}
	for g := range p.retired {
		if !g.retired || g.count <= 0 || g.members != 0 {
			return fmt.Errorf("retired registration %s#%d: retired %v, count %d, members %d", g.rule, g.serial, g.retired, g.count, g.members)
		}
		all = append(all, g)
	}
	sum := 0
	carried := map[*registration]int{}
	flows := map[*Listener]int{}
	for _, g := range all {
		cs := 0
		for c := range g.cells {
			if c.reg != g || c.n <= 0 {
				return fmt.Errorf("cell of %s#%d points at %s#%d with n %d", g.rule, g.serial, c.reg.rule, c.reg.serial, c.n)
			}
			if _, ok := c.l.cells[c]; !ok {
				return fmt.Errorf("cell of %s#%d is missing from its listener", g.rule, g.serial)
			}
			cs += c.n
			flows[c.l] += c.n
			if c.l.counted {
				if g.retired {
					return fmt.Errorf("retired registration %s#%d holds %d flows carried by an accepting listener", g.rule, g.serial, c.n)
				}
				carried[c.l.reg] += c.n
			}
		}
		if cs != g.count {
			return fmt.Errorf("registration %s#%d: cells %d, a_g %d", g.rule, g.serial, cs, g.count)
		}
		sum += g.count
	}
	if sum != p.inUse {
		return fmt.Errorf("registrations hold %d, u = %d", sum, p.inUse)
	}
	for l, n := range flows {
		if l.flows != n {
			return fmt.Errorf("listener %s: cells %d, flows %d", l.rule, n, l.flows)
		}
	}
	m := minimumFor(p.total, len(p.regs))
	var s, sf, ks, kf int
	for _, g := range p.regs {
		if carried[g] != g.carried {
			return fmt.Errorf("registration %s#%d: c_g %d, rebuilt %d", g.rule, g.serial, g.carried, carried[g])
		}
		if d := m - g.count; d > 0 {
			s += d
			ks++
		}
		if d := FlowFloor - g.count; d > 0 {
			sf += d
			kf++
		}
	}
	if m != p.minimum || s != p.unfilled || sf != p.floorShort || ks != p.unfilledRegs || kf != p.floorShortRegs {
		return fmt.Errorf("kept m %d S %d Sf %d kS %d kf %d, rebuilt m %d S %d Sf %d kS %d kf %d",
			p.minimum, p.unfilled, p.floorShort, p.unfilledRegs, p.floorShortRegs, m, s, sf, ks, kf)
	}
	return nil
}
