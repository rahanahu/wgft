//go:build !race

package wgbind

// raceEnabled は race detector の下で動いているかを表す。
const raceEnabled = false
