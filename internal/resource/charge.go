package resource

// Charge はフロー 1 本が持つ 2 つの枠をまとめて持つ。1 つは Admission Policy の送信元ごとの同時フロー数の
// 枠で、評価器の手形を返す関数として呼び出し側から受け取る。もう 1 つは Resource Guard の枠(Lease)で
// ある。中継は policy、Pool の順に取り(設計文書 7a.10 節)、Release は逆の Lease、policy の順に、
// 持っている枠を返す。
//
// Release はフローの終わりに 1 度だけ呼ぶ。2 度目の呼び出しも Lease.Release と policy の関数にそのまま
// 渡し、Charge の側では 1 度に丸めない。丸めると、二重の返却が Pool の帳簿(Ledger.DoubleReleases)から
// 消えるためである。ゼロ値は枠を何も持たない Charge で、その Release は何もしない。
type Charge struct {
	policy func()
	lease  *Lease
}

// HoldPolicy は Admission Policy の枠を返す関数を持たせる。
func (c *Charge) HoldPolicy(release func()) { c.policy = release }

// HoldLease は Take が渡した Pool の枠を持たせる。
func (c *Charge) HoldLease(x *Lease) { c.lease = x }

// Release は Lease、policy の順に、持っている枠を返す。
func (c *Charge) Release() {
	if c.lease != nil {
		c.lease.Release()
	}
	if c.policy != nil {
		c.policy()
	}
}
