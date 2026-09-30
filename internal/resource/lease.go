package resource

// registration はルールの登録。ルール ID が受け付けている listener を 1 つ以上持ち続ける期間で、
// 受け付けている listener が 0 個になった時点で退役し、以後 A に戻らない(設計文書 7a.10 節)。
type registration struct {
	serial  int
	rule    string
	members int  // 受け付けている listener の数
	retired bool // 退役した
	count   int  // a_g
	carried int  // c_g
	cells   map[*cell]struct{}
}

// cell は listener と登録の組ごとのフローの数。Lease は cell を指す。listener が運ぶフローは、取得の
// 後は変わらずその listener が運ぶ。帰属の規則で移るのは cell の登録だけである。
type cell struct {
	l   *Listener
	reg *registration
	n   int
}

// Lease はフロー 1 つ分の枠。フローの終わりに Release を 1 度だけ呼ぶ。
type Lease struct {
	l    *Listener
	c    *cell
	done bool // Pool の排他で守る
}

// Release は枠を返す。2 度目以降は偽を返し、帳簿を変えない。
func (x *Lease) Release() bool {
	l := x.l
	p := l.p
	p.mu.Lock()
	defer p.mu.Unlock()
	if x.done {
		p.doubleReleases++
		return false
	}
	x.done = true
	p.inUse--
	l.flows--
	if l.counted {
		l.reg.carried--
	}
	c := x.c
	c.n--
	if c.n == 0 {
		delete(c.reg.cells, c)
		delete(l.cells, c)
		if l.cur == c {
			l.cur = nil
		}
	}
	p.addCountLocked(c.reg, -1)
	return true
}

// cellFor は listener の今の登録の cell。無ければ作る。
func (p *Pool) cellFor(l *Listener) *cell {
	if l.cur != nil && l.cur.reg == l.reg {
		return l.cur
	}
	c := &cell{l: l, reg: l.reg}
	if l.cells == nil {
		l.cells = map[*cell]struct{}{}
	}
	l.cells[c] = struct{}{}
	l.reg.cells[c] = struct{}{}
	l.cur = c
	return c
}

// moveCellLocked は cell の登録を移す(退役した登録のフローの帰属の規則)。u と c_g は変わらない。
func (p *Pool) moveCellLocked(c *cell, to *registration) {
	from := c.reg
	delete(from.cells, c)
	p.addCountLocked(from, -c.n)
	c.reg = to
	to.cells[c] = struct{}{}
	p.addCountLocked(to, c.n)
}

// attachLocked は開いていて受け付けている listener を今のルールの登録に加える(登録、受け付けの
// 開始と再開、付け替えの後)。登録が無ければ新しい登録を作り、N が変わるので S を作り直す。加わった
// 後、この listener が運ぶフローのうち退役した登録にあるものを、加わった登録へ移す(加入の発火)。
func (p *Pool) attachLocked(l *Listener) {
	if l.counted || !l.open || !l.accepting {
		return
	}
	g := p.regs[l.rule]
	if g == nil {
		p.regSerial++
		g = &registration{serial: p.regSerial, rule: l.rule, cells: map[*cell]struct{}{}}
		p.regs[l.rule] = g
		p.refreshLocked()
	}
	g.members++
	g.carried += l.flows
	l.reg = g
	l.counted = true
	for c := range l.cells {
		if c.reg.retired {
			p.moveCellLocked(c, g)
		}
	}
}

// detachLocked は listener を登録から外す(閉鎖、受け付けの停止、付け替えの前)。登録の受け付けて
// いる listener が 0 個になれば、登録は退役し、N が変わるので S を作り直す。退役した登録のフローの
// うち、受け付けている listener が運ぶものを、その listener の今の登録へ移す(退役の発火)。
func (p *Pool) detachLocked(l *Listener) {
	if !l.counted {
		return
	}
	g := l.reg
	g.members--
	g.carried -= l.flows
	l.reg = nil
	l.counted = false
	if g.members > 0 {
		return
	}
	g.retired = true
	delete(p.regs, g.rule)
	p.refreshLocked()
	if g.count > 0 {
		p.retired[g] = struct{}{}
	}
	for c := range g.cells {
		if c.l.counted {
			p.moveCellLocked(c, c.l.reg)
		}
	}
}
