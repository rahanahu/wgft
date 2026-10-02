// Package controlapi holds the wire shapes and constants of the agent's control socket
// (design.md 9 節 and 10.2c 節): the socket's path rule, the one-line `doctor` request and the
// JSON reply it answers with, the cap on each string in that reply, the kernel-mode reading that
// reply carries, the bound on how much of a reply a reader takes, and the tunnel reasons a reader
// matches against.
//
// internal/agent serves this socket and builds the reply; cmd/wgft's `agent doctor` and
// `agent rotate-key` read it. The declarations live in this separate package so the reader can
// depend on the shapes without depending on the running agent, the same way internal/vpsd/adminapi
// separates the admin API's read model from internal/vpsd/admin (design.md 7a.7 節).
//
// Nothing here touches the agent's runtime state, a dataplane or the kernel: these are plain
// shapes and constants, and the one function that reads a reply line. The functions that build
// the reply stay in internal/agent (collectDoctor, runtimeStateLocked, ReadKernel).
package controlapi
