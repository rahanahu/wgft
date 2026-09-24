package agent

import (
	"log"

	"github.com/rahanahu/wgft/internal/agent/credentials"
)

// removeLeftoverTemps は、保存の途中の強制終了で残った認証情報ファイルの一時ファイルを消す(仕様 9 節)。
// 呼び出し側は認証情報ファイルのロックを持つ。消した件数だけをログに出し、パスと中身は出さない。
// 消せないファイルがあっても起動は止めない。
func removeLeftoverTemps(held *credentials.Lock, credentialsPath string) {
	n, err := credentials.RemoveLeftoverTemps(held, credentialsPath)
	if n > 0 {
		log.Printf("removed leftover temporary copies of the credentials file left by interrupted saves: %d", n)
	}
	if err != nil {
		log.Printf("warning: cannot remove leftover temporary copies of the credentials file: %v; "+
			"they hold the WireGuard private key and the permanent token, so remove the .wgft-credentials-* files in the data directory by hand", err)
	}
}
