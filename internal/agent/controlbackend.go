package agent

import (
	"context"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/control"
)

// controlBackend は制御ソケットのサーバ(internal/agent/control)に実行時の状態を渡す。
type controlBackend struct{ rt *runtime }

// RotateKey は rotateKey を呼ぶ。panic を受け止めない(理由は control.ServeConn にある)。
func (b controlBackend) RotateKey() (wgtypes.Key, error) { return b.rt.rotateKey() }

// DoctorLine は doctorResponseLine を呼ぶ。panic の受け止めは doctorResponseLine の中にある。
func (b controlBackend) DoctorLine() []byte { return b.rt.doctorResponseLine() }

// serveControl は制御ソケットを開き、ctx が終わるまで指示を受ける。
func (rt *runtime) serveControl(ctx context.Context) {
	control.Serve(ctx, rt.opts.CredentialsPath, controlBackend{rt})
}
