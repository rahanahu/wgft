//go:build !windows

package credentials

// secureNewDir は Windows 以外では何もしない。ディレクトリのパーミッションは
// EnsureDataDir が MkdirAll に渡す 0700 で足りる。
func secureNewDir(dir string) error { return nil }
