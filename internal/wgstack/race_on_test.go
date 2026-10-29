//go:build race

package wgstack

// raceEnabled は -race の build で真になる。重い試験は回数を減らす。
const raceEnabled = true
