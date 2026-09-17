//go:build windows

package main

import (
	"os"
	"path/filepath"
)

// 既定の置き場(仕様 11a 節)。Windows はデータも設定も %ProgramData%\wgft に置く。
func defaultDataDir() string {
	d := os.Getenv("ProgramData")
	if d == "" {
		d = `C:\ProgramData`
	}
	return filepath.Join(d, "wgft")
}
func defaultConfigDir() string         { return defaultDataDir() }
func joinPath(dir, name string) string { return filepath.Join(dir, name) }
