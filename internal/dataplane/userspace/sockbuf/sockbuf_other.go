//go:build !linux

package sockbuf

import "errors"

// supported は、この OS で測る手段を持つかどうかである。Linux 以外では、得られる値を決める仕組みを
// 確かめていないので測らない(設計文書 7 節)。
const supported = false

// errUnsupported は、Linux 以外で測ろうとしたときの誤りである。
var errUnsupported = errors.New("socket buffers are measured on Linux only")

// Measure は Linux 以外では測らず、Supported が偽の結果を返す。
func Measure(port uint16) Reading { return Reading{Port: port} }

// ReadLimits は Linux 以外では読まない。
func ReadLimits() Limits { return Limits{RmemErr: errUnsupported, WmemErr: errUnsupported} }

// PlainProbe は Linux 以外では試さない。
func PlainProbe() Probe { return Probe{Err: errUnsupported} }
