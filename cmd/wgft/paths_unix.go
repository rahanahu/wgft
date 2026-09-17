//go:build !windows && !darwin

package main

// 既定の置き場(仕様 11a 節)。Linux とその他の Unix。
func defaultDataDir() string           { return "/var/lib/wgft" }
func defaultConfigDir() string         { return "/etc/wgft" }
func joinPath(dir, name string) string { return dir + "/" + name }
