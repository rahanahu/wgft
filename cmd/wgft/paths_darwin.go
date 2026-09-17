//go:build darwin

package main

import (
	"os"
	"path/filepath"
)

// 既定の置き場(仕様 11a 節)。macOS はエージェントを利用者の権限で動かす前提で、データも設定も
// ~/Library/Application Support/wgft に置く。
func defaultDataDir() string {
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "wgft")
	}
	return "wgft"
}
func defaultConfigDir() string         { return defaultDataDir() }
func joinPath(dir, name string) string { return filepath.Join(dir, name) }
