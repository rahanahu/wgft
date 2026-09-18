//go:build !windows

package credentials

import "os"

// createSecureTemp は Windows 以外では os.CreateTemp そのもの。os.CreateTemp は作成の
// 瞬間からモード 0600 で開くため、これだけで既に安全であり、Windows のように作成後に
// 別途締め直す必要が無い(仕様 11a 節)。
func createSecureTemp(dir, pattern string) (*os.File, error) {
	return os.CreateTemp(dir, pattern)
}
