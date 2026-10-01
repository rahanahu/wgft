package store

import "testing"

// TestMetaKeysKeepTheirStoredNames pins every meta key to the string an existing server database
// already holds. The keys are names inside the database file, so renaming one makes a server that
// was upgraded in place lose that record: a new server key would be generated, the recorded mode
// and address range would be read as absent, and teardown would forget its hints.
func TestMetaKeysKeepTheirStoredNames(t *testing.T) {
	want := map[string]string{
		MetaGeneration:           "generation",
		MetaServerKey:            "wg_server_private_key",
		MetaMode:                 "mode",
		MetaWGAddress:            "wg_address",
		MetaTeardownWGInterface:  "teardown_wg_interface",
		MetaTeardownWGPort:       "teardown_wg_port",
		MetaTeardownAgentAPIPort: "teardown_agent_api_port",
		MetaIPForwardSetAt:       "ip_forward_set_by_wgft_at",
		MetaAgentAPICert:         "agent_api_cert_pem",
		MetaAgentAPIKey:          "agent_api_key_pem",
	}
	// A map literal with a repeated constant key does not compile, so two keys sharing one name
	// is caught here too.
	for got, name := range want {
		if got != name {
			t.Errorf("meta key %q, want %q as stored in existing databases", got, name)
		}
	}
	if ModeKernel != "kernel" || ModeUserspace != "userspace" {
		t.Errorf("recorded mode values are %q and %q, want kernel and userspace", ModeKernel, ModeUserspace)
	}
}
