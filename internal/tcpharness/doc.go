// Package tcpharness runs the same TCP scenarios against several TCP engines, so that an engine
// for wgft's agent can be judged against Linux, the reference, by numbers. The rules it follows
// are in docs/design/userspace/wgstack-verification.md.
//
// The testbench speaks raw IPv4 to a DUT (dut.go), the way the WireGuard tunnel does: it injects
// crafted segments and checks what the engine emits, while the DUT's socket API plays wgft's
// relay. Only the shapes of TCP the agent terminates are in scope: passive open, IPv4, the fixed
// tunnel MTU. Each engine has an adapter package, gvisordut for internal/nettun's gVisor Device
// and linuxdut for the kernel through a TUN device, and an expected-difference list keyed by
// "scenario/check" whose entries record what the engine does instead and why.
//
// Check lines are logged as PASS, FAIL, KNOWN DIFFERENCE, CHANGED DIFFERENCE or UNEXPECTED PASS,
// and measured values as MEASURE lines for comparison tables. The run's seed is logged and
// SeedEnv replays it. The scenarios follow the RFCs and the black-box approach of gVisor's
// packetimpact suite; they are wgft's own and copy no gVisor test code.
package tcpharness
