package vpsd

import (
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/platform/linux"
	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/internal/vpsd/conncheck"
	"github.com/rahanahu/wgft/internal/vpsd/proxyrelay"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// stubDataplane implements serverDataplane with no-op methods. It stands in for kernelDataplane,
// which never tracks UDP flows in a resource.Pool (design.md 7a.10 節「kernel 側の保護」): it does
// not implement udpPooler, matching that kernel mode has no Go-side UDP budget.
type stubDataplane struct{}

func (stubDataplane) EnsureDevice(dataplane.WGConfig) ([]string, error) { return nil, nil }
func (stubDataplane) WGStatus() (*wgtypes.Device, error)                { return nil, nil }
func (stubDataplane) OtherDeviceWithKey(wgtypes.Key) (string, bool)     { return "", false }
func (stubDataplane) ReadUDPTimeouts() (linux.UDPTimeouts, error)       { return linux.UDPTimeouts{}, nil }
func (stubDataplane) Inspect() (*linux.Report, error)                   { return &linux.Report{}, nil }
func (stubDataplane) BoundPorts() (linux.Bound, error)                  { return linux.Bound{}, nil }
func (stubDataplane) InputPortSuggestions(proto.PortRange, proto.Proto) ([]string, error) {
	return nil, nil
}
func (stubDataplane) participant() dataplane.Participant          { return nil }
func (stubDataplane) EnableIPForward(*store.Store) *linux.Finding { return nil }
func (stubDataplane) ConntrackWarning() string                    { return "" }
func (stubDataplane) CheckConnectivity(string) conncheck.Result   { return conncheck.Result{} }

// udpPoolDataplane additionally implements udpPooler, standing in for userspaceDataplane.
type udpPoolDataplane struct {
	stubDataplane
	pool *resource.Pool
}

func (d udpPoolDataplane) UDPPool() *resource.Pool { return d.pool }

// Kernel mode has no Go-side UDP pool: d.dp does not implement udpPooler, so FlowBudget must have no
// "udp" entry, and no UDP rule can ever appear in Refusals (design.md 7a.10 節「kernel 側の保護」).
// TCP always has one, from d.proxy (the server's Relay frontend).
func TestResourceStatusKernelModeHasNoUDPPool(t *testing.T) {
	d := &Daemon{dp: stubDataplane{}, proxy: proxyrelay.New(proxyrelay.Options{Pool: resource.NewPool(2048)})}
	st := d.ResourceStatus()
	if _, ok := st.FlowBudget[proto.UDP]; ok {
		t.Errorf("kernel mode must not report a udp flow_budget entry, got %+v", st.FlowBudget)
	}
	got, ok := st.FlowBudget[proto.TCP]
	if !ok || got.Limit != 2048 {
		t.Errorf("tcp flow_budget = %+v, ok=%v, want Limit=2048", got, ok)
	}
}

// Userspace mode has both pools, and reports refusals of several reasons for the same rule.
func TestResourceStatusUserspaceModeHasBothPools(t *testing.T) {
	udpPool := resource.NewPool(8192)
	tcpPool := resource.NewPool(2048)

	// Two rules compete for the TCP pool so that the isolation cap (rule_cap) can trigger, then push
	// past both the cap and the reserve to exercise every reason (design.md 7a.10 節).
	lFlood := tcpPool.Listener("r_flood")
	lOther := tcpPool.Listener("r_other")
	if _, ok := lOther.Acquire(); !ok {
		t.Fatal("r_other's first flow must be admitted")
	}
	for i := 0; i < 2048; i++ {
		lFlood.Acquire() // fills the rule cap, then the reserve, then the whole budget
	}
	refusal, ok := lFlood.Acquire()
	if ok {
		t.Fatal("r_flood must be refused once the budget and its cap are exhausted")
	}
	if refusal.Reason == "" {
		t.Fatal("a refusal must carry a reason")
	}

	d := &Daemon{
		dp:    udpPoolDataplane{pool: udpPool},
		proxy: proxyrelay.New(proxyrelay.Options{Pool: tcpPool}),
	}
	st := d.ResourceStatus()

	udpBudget, ok := st.FlowBudget[proto.UDP]
	if !ok || udpBudget.Limit != 8192 || udpBudget.InUse != 0 {
		t.Errorf("udp flow_budget = %+v, ok=%v, want {InUse:0 Limit:8192}", udpBudget, ok)
	}
	tcpBudget, ok := st.FlowBudget[proto.TCP]
	if !ok || tcpBudget.Limit != 2048 {
		t.Errorf("tcp flow_budget = %+v, ok=%v, want Limit=2048", tcpBudget, ok)
	}

	byReason, ok := st.Refusals["r_flood"]
	if !ok || len(byReason) == 0 {
		t.Fatalf("r_flood must have at least one refusal reason recorded, got %+v", st.Refusals)
	}
	var total uint64
	for _, n := range byReason {
		total += n
	}
	if total == 0 {
		t.Errorf("r_flood's refusal counts must sum to more than zero, got %+v", byReason)
	}
	if _, ok := st.Refusals["r_other"]; ok {
		t.Errorf("r_other was never refused and must be absent from Refusals, got %+v", st.Refusals["r_other"])
	}
}
