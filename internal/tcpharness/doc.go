// Package tcpharness runs the same TCP scenarios against several TCP engines, so that an engine
// for wgft's agent can be judged against Linux, the reference, by numbers.
//
// The testbench speaks raw IPv4 to a DUT (dut.go), the way the WireGuard tunnel does: it injects
// crafted segments and checks what the engine emits, while the DUT's socket API plays wgft's
// relay. Only the shapes of TCP the agent terminates are in scope: passive open, IPv4, the fixed
// tunnel MTU. Each engine has an adapter package (gvisordut for internal/nettun's gVisor Device,
// linuxdut for the kernel through a TUN device) and an expected-difference list, keyed by
// "scenario/check", of the checks known to fail on it, each with its reason.
//
// The scenarios follow the RFCs and the black-box approach of gVisor's packetimpact suite; they
// are wgft's own and copy no gVisor test code. Check lines are logged as PASS, FAIL, KNOWN
// DIFFERENCE or UNEXPECTED PASS, and measured values as MEASURE lines for comparison tables.
package tcpharness
