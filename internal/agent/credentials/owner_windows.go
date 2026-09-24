package credentials

// keepOwner は Windows では何もしない。Windows の agent.json の保護は DACL で行う(仕様 11a 節)。
func keepOwner(tmp, path string) error { return nil }
