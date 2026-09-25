package agent

import (
	"log"

	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/startup"
)

// kernelModeAvailable は、このビルドがエージェントのカーネルモードの dataplane を持つかどうかである
// (Linux のビルドだけが持つ。dataplane_kernel.go)。偽なら、関門を通った kernel の指定も記録する前に
// 止める。記録してから止めると、ユーザー空間モードへ戻すために、まだ残骸の無いホストで撤去が要る。
// テストだけが書き換える。
var kernelModeAvailable = kernelModeBuilt

// reconcileMode は、認証情報ファイルに記録したモード recorded と、設定の WGFT_MODE の値 want を照合する
// (仕様 9・11a 節)。want が空なら設定は省略されており、ユーザー空間モードを指す。カーネルモードは明示した
// ときだけ選ばれる。返す mode は起動するモード、record は記録を書き換える必要があるかどうかである。
//
// 関門は記録だけを根拠に判定する(11a 節)。ユーザー空間モードのエージェントは CAP_NET_ADMIN を持たず、
// WireGuard インタフェースもテーブルも読めないためである。カーネルモードの記録は、それ自体が残骸の 1 つで
// あり、撤去(wgft agent teardown)だけが消す。
//
//   - 記録と一致すれば、そのまま起動する
//   - userspace から kernel への切り替えは残骸を生まないので通し、記録を書き換える
//   - kernel から userspace への切り替えは、種別 mode-gate で拒否する。WGFT_MODE を省略した場合も同じで、
//     文面は WGFT_MODE=kernel を設定する道と、撤去してから切り替える道の両方を示す
//
// 記録が kernel でも userspace でもない値なら、認証情報ファイルと設定が矛盾するものとして拒否する。撤去も
// この記録を消さずに止まる(teardown.go)ので、文面は撤去を案内しない。
// want が kernel でも userspace でも空でもなければ、種別 config で拒否する。
func reconcileMode(recorded, want string) (mode string, record bool, err error) {
	have := recorded
	if have == "" {
		have = credentials.ModeUserspace
	}
	mode = want
	switch mode {
	case "":
		mode = credentials.ModeUserspace
	case credentials.ModeKernel, credentials.ModeUserspace:
	default:
		// 入口(cmd/wgft の buildAgentOptions)が先に弾くが、記録を書き換える前の守りとしてここでも弾く
		return "", false, startup.Config("WGFT_MODE", "must be kernel or userspace, not %q", want)
	}
	switch have {
	case credentials.ModeKernel, credentials.ModeUserspace:
	default:
		return "", false, startup.Conflict("WGFT_MODE",
			"the credentials file agent.json records the mode %q, which is neither kernel nor userspace; it may have been written by a newer version of wgft, and agent teardown leaves it too; "+
				"start the version that wrote it, or restore agent.json from a backup", have)
	}
	switch {
	case have == mode:
		return mode, false, nil
	case have == credentials.ModeUserspace:
		return mode, true, nil
	case want == "":
		return "", false, startup.ModeGate("WGFT_MODE",
			"WGFT_MODE is unset, which means userspace, but the credentials file agent.json records kernel mode; "+
				"set WGFT_MODE=kernel to keep kernel mode, or run wgft agent teardown first, which removes the kernel-mode WireGuard interface, table inet wgft_agent and the record, and then start in userspace mode")
	default:
		return "", false, startup.ModeGate("WGFT_MODE",
			"changing mode from kernel to userspace: the credentials file agent.json records kernel mode, and its WireGuard interface and table inet wgft_agent may remain; "+
				"run wgft agent teardown first, which removes them and the record, or set WGFT_MODE=kernel to keep kernel mode")
	}
}

// enterMode は起動時に reconcileMode を通し、カーネルモードならホストの前提を確かめ、必要なら記録を
// 書き換えて保存する。起動するモードを返す。呼び出し側は、認証情報ファイルの排他を取った後、鍵を作る
// よりも、登録よりも、カーネルに何かを書くよりも前に呼ぶ。
// カーネルモードの記録を最初の書き込みより前に残すので、途中で落ちても関門は残骸を見落とさない。
func enterMode(f *credentials.Credentials, want, path string) (string, error) {
	mode, record, err := reconcileMode(f.Mode, want)
	if err != nil {
		return "", err
	}
	if mode == credentials.ModeKernel && !kernelModeAvailable {
		return "", startup.Prerequisite("WGFT_MODE", "this build does not include the agent's kernel mode yet, so it cannot start in kernel mode; use a build that includes it")
	}
	// カーネルモードの前提は、記録を書き換えるより前に確かめる。Run は登録をこの後に行うので、登録より
	// 前でもある。前提で止まる起動が記録を残すと、案内どおりユーザー空間モードへ戻す起動が関門に
	// 止められ、撤去には root が要る。カーネルには何も作られていないのに、戻す道が閉じる(仕様 11a 節)
	if mode == credentials.ModeKernel {
		if err := kernelPrerequisites(); err != nil {
			return "", err
		}
	}
	if !record {
		return mode, nil
	}
	log.Printf("changing mode from %s to %s; recording it in the credentials file", f.RecordedMode(), mode)
	f.Mode = mode
	if err := f.Save(path); err != nil {
		return "", err
	}
	return mode, nil
}
