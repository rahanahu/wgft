package agent

import (
	"log"

	"github.com/rahanahu/wgft/internal/agent/credentials"
)

// removeLeftoverTemps は、保存の途中の強制終了で残った認証情報ファイルの一時ファイルを消す(仕様 9 節)。
// 呼び出し側は認証情報ファイルのロックを持つ。ログは 1 行ずつで、件数と誤りの種類だけを出し、パスと
// 中身は出さない。消せないファイルがあっても起動は止めない。
func removeLeftoverTemps(held *credentials.Lock, credentialsPath string) {
	r, err := credentials.RemoveLeftoverTemps(held, credentialsPath)
	if err != nil {
		log.Printf("warning: could not check the data directory for leftover temporary copies of the credentials file: %s; "+
			"such copies hold the WireGuard private key and the permanent token, so look for .wgft-credentials-* files there and remove them by hand", credentials.ErrorKind(err))
		return
	}
	if r.Removed > 0 {
		log.Printf("removed leftover temporary copies of the credentials file left by interrupted saves: %d", r.Removed)
	}
	if r.Failed > 0 {
		log.Printf("warning: cannot remove leftover temporary copies of the credentials file: %d, first error: %s; "+
			"they hold the WireGuard private key and the permanent token, so remove the .wgft-credentials-* files in the data directory by hand", r.Failed, credentials.ErrorKind(r.FirstFailure))
	}
}
