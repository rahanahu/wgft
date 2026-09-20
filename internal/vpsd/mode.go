package vpsd

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/wg"
	"github.com/rahanahu/wgft/internal/startup"
	"github.com/rahanahu/wgft/internal/vpsd/store"
)

// モードとアドレス帯の初回記録・照合(仕様 9・11a 節)。
const (
	modeMeta      = "mode"
	wgAddressMeta = "wg_address"
	modeKernel    = "kernel"
	modeUserspace = "userspace"
)

// reconcileModeAndAddress は、モードとアドレス帯を SQLite に記録し、以後は起動のたびに照合する。
// 再試行では直らない拒否は *startup.Refusal で返し、終了コード 3 に写させる(設計文書 11b 節)。
// SQLite の誤りは、再試行が直しうるのでそのまま返す。
// hadServerKey は「この起動より前に SQLite が使われていたか」(サーバ鍵の有無で判断)。
func reconcileModeAndAddress(st *store.Store, opts Options, hadServerKey bool) error {
	// --- モード ---
	stored, err := st.GetMeta(modeMeta)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// 記録が無い。既存の SQLite(鍵あり)はこれまで kernel しか存在しなかったので kernel とみなす。
		mode := opts.Mode
		if mode == "" {
			if hadServerKey {
				mode = modeKernel
				log.Printf("existing server database with no recorded mode; recording it as kernel")
			} else {
				// 値が無いことは値だけからは判定できない。記録の有無を見て初めて必須になるので、
				// 入口(cmd/wgft の buildServerOptions)ではなく、ここで判定する(設計文書 11b 節)。
				return startup.Config("WGFT_MODE", "set it (--mode) to kernel or userspace on the first start")
			}
		}
		// 値そのものの誤りは入口で弾いてある。ここは、入口を通らない呼び出し(単体テスト、将来の
		// 別の呼び出し元)に対する二重の守りとして残す。
		if mode != modeKernel && mode != modeUserspace {
			return startup.Config("WGFT_MODE", "must be kernel or userspace, not %q", mode)
		}
		if err := checkModeSupported(mode); err != nil {
			return err
		}
		if err := st.SetMeta(modeMeta, []byte(mode)); err != nil {
			return err
		}
	case err != nil:
		return fmt.Errorf("checking mode: %w", err)
	default:
		want := opts.Mode
		have := string(stored)
		if want == "" {
			want = have
			log.Printf("WGFT_MODE unset; starting with the recorded mode %s", have)
		}
		if want != have {
			// 食い違い:関門を通れば記録を書き換えて起動、通らなければ拒否(3.3 節)。
			residue, known := wgResidue(opts.WGInterface)
			allow, reason := modeGate(have, want, residue, known)
			if !allow {
				return startup.ModeGate("WGFT_MODE", "changing mode from %s to %s: %s", have, want, reason)
			}
			log.Printf("changing mode from %s to %s (%s)", have, want, reason)
			if err := st.SetMeta(modeMeta, []byte(want)); err != nil {
				return err
			}
		}
		if err := checkModeSupported(want); err != nil {
			return err
		}
	}

	// --- wg のアドレス帯 ---
	addr, err := st.GetMeta(wgAddressMeta)
	switch {
	case errors.Is(err, store.ErrNotFound):
		if err := st.SetMeta(wgAddressMeta, []byte(opts.WGAddress)); err != nil {
			return err
		}
	case err != nil:
		return fmt.Errorf("checking address range: %w", err)
	default:
		if string(addr) != opts.WGAddress {
			return startup.Conflict("WGFT_WG_ADDRESS", "wg address range differs from the recorded one (%s vs %s); changing it needs teardown --purge and re-registration", addr, opts.WGAddress)
		}
	}
	return nil
}

// checkModeSupported は、実装済みのモードだけを通す(kernel と userspace。仕様 6.1 節と 6.3 節)。
func checkModeSupported(mode string) error {
	switch mode {
	case modeKernel, modeUserspace:
		return nil
	}
	return startup.Config("WGFT_MODE", "unknown mode %q", mode)
}

// modeGate は、記録済み stored と要求 want が食い違うときの関門(3.3 節)。
// residue は wg の残骸(インタフェース・テーブル)の有無、known はそれを確かめられたか。
func modeGate(stored, want string, residue, known bool) (allow bool, reason string) {
	if stored == modeKernel && want == modeUserspace {
		if known && residue {
			return false, "a kernel wg interface or table inet wgft remains; run server teardown first"
		}
		if !known {
			return true, "cannot confirm leftovers, so proceeding to bind; if the port is held, suspect leftovers and run server teardown on the host"
		}
		return true, "no kernel leftovers"
	}
	// userspace -> kernel は残骸の心配が無いので通す。
	return true, "userspace to kernel has no leftovers concern"
}

// wgResidue は、指定インタフェースの kernel wg が残っているかを返す(known=false なら確認できなかった)。
func wgResidue(iface string) (residue, known bool) {
	_, err := wg.Status(iface)
	return classifyWGResidue(err)
}

// classifyWGResidue is wgResidue's error classification, split out so it can be unit-tested
// without a real wg device (this package has no netlink test double). wgctrl's Device()
// documents its interface-not-found error as wrapping os.ErrNotExist (internal/wglinux's
// client_linux.go: "compatible with os.ErrNotExist for easy checking"), so errors.Is is the
// correct, typed check here; the previous strings.Contains on the error text risked reading an
// unrelated failure's message (e.g. a permission or netlink error that happens to mention "not
// found") as a confirmed absence, which would wrongly let a kernel-to-userspace mode switch
// through modeGate (design.md 10.5 節; 3.3 節 for the gate itself).
func classifyWGResidue(err error) (residue, known bool) {
	switch {
	case err == nil:
		return true, true
	case errors.Is(err, os.ErrNotExist):
		return false, true
	default:
		return false, false
	}
}
