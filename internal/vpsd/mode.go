package vpsd

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/internal/vpsd/wg"
)

// モードとアドレス帯の初回記録・照合(仕様 9・11a 節)。
const (
	modeMeta      = "mode"
	wgAddressMeta = "wg_address"
	modeKernel    = "kernel"
	modeUserspace = "userspace"
)

// reconcileModeAndAddress は、モードとアドレス帯を SQLite に記録し、以後は起動のたびに照合する。
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
				log.Printf("existing state file with no recorded mode; recording it as kernel")
			} else {
				return fmt.Errorf("set WGFT_MODE (--mode) to kernel or userspace")
			}
		}
		if mode != modeKernel && mode != modeUserspace {
			return fmt.Errorf("WGFT_MODE must be kernel or userspace (%q)", mode)
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
				return fmt.Errorf("changing mode from %s to %s: %s", have, want, reason)
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
			return fmt.Errorf("wg address range differs from the recorded one (%s vs %s); changing it needs teardown --purge and re-registration", addr, opts.WGAddress)
		}
	}
	return nil
}

// checkModeSupported は、v0.1 で動くモードだけを通す。userspace は v0.2.0 で実装予定(仕様 13 節)。
func checkModeSupported(mode string) error {
	if mode == modeUserspace {
		return fmt.Errorf("userspace mode is planned for v0.2.0; only kernel is available now")
	}
	return nil
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
	if err == nil {
		return true, true
	}
	msg := err.Error()
	if strings.Contains(msg, "no such") || strings.Contains(msg, "not exist") || strings.Contains(msg, "not found") {
		return false, true
	}
	return false, false
}
