package wgstack

import "math/bits"

// sipKey は SipHash-2-4 の 128 bit の鍵。表の hash の種と ISN の鍵(RFC 6528)に使い、作成の時に
// 渡された乱数から作る。相手が選ぶ送信元のアドレスとポートで、hash の衝突を集められないようにする。
type sipKey struct{ k0, k1 uint64 }

func sipRound(v0, v1, v2, v3 uint64) (uint64, uint64, uint64, uint64) {
	v0 += v1
	v1 = bits.RotateLeft64(v1, 13)
	v1 ^= v0
	v0 = bits.RotateLeft64(v0, 32)
	v2 += v3
	v3 = bits.RotateLeft64(v3, 16)
	v3 ^= v2
	v0 += v3
	v3 = bits.RotateLeft64(v3, 21)
	v3 ^= v0
	v2 += v1
	v1 = bits.RotateLeft64(v1, 17)
	v1 ^= v2
	v2 = bits.RotateLeft64(v2, 32)
	return v0, v1, v2, v3
}

// sum は 16 byte の入力 m0、m1(little endian の 2 語)の SipHash-2-4 を返す。
func (k sipKey) sum(m0, m1 uint64) uint64 {
	v0 := k.k0 ^ 0x736f6d6570736575
	v1 := k.k1 ^ 0x646f72616e646f6d
	v2 := k.k0 ^ 0x6c7967656e657261
	v3 := k.k1 ^ 0x7465646279746573
	for _, m := range [3]uint64{m0, m1, 16 << 56} {
		v3 ^= m
		v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
		v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
		v0 ^= m
	}
	v2 ^= 0xff
	for range 4 {
		v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	}
	return v0 ^ v1 ^ v2 ^ v3
}

// hashTuple は 4 つ組の鍵付きの hash を返す。
func (k sipKey) hashTuple(t tuple) uint64 {
	return k.sum(uint64(t.laddr)|uint64(t.raddr)<<32, uint64(t.lport)|uint64(t.rport)<<16)
}
