package detect

import (
	"testing"

	"scrubd/internal/inspect"
	runtimeinv "scrubd/internal/runtime"
)

func TestDetectStaleFirewallRules(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{
			NetworkInterfaces: []inspect.NetworkInterface{{Name: "eth0"}},
			FirewallRules: []inspect.FirewallRule{{
				Backend:       "iptables",
				Table:         "nat",
				Chain:         "CNI-HOSTPORT-DNAT",
				Raw:           "-A CNI-HOSTPORT-DNAT -i br-deadbeef -j RETURN",
				InterfaceRefs: []string{"br-deadbeef"},
				Source:        "iptables-save",
			}},
		},
		Runtimes: availableRuntimeInventory(),
	}

	leaks := DetectStaleFirewallRules(input)
	if len(leaks) != 1 {
		t.Fatalf("len(leaks) = %d, want 1", len(leaks))
	}
	if leaks[0].Type != LeakTypeFirewallRule || leaks[0].Resource != "iptables nat CNI-HOSTPORT-DNAT br-deadbeef" {
		t.Fatalf("unexpected leak: %#v", leaks[0])
	}
	if len(leaks[0].CleanupPlan) != 0 {
		t.Fatalf("cleanup plan = %#v, want none for firewall rule", leaks[0].CleanupPlan)
	}
}

func TestDetectStaleFirewallRulesSkipsPresentInterface(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{
			NetworkInterfaces: []inspect.NetworkInterface{{Name: "br-active"}},
			FirewallRules: []inspect.FirewallRule{{
				Backend:       "nftables",
				Table:         "ip/nat",
				Chain:         "postrouting",
				Raw:           `oifname "br-active" masquerade`,
				InterfaceRefs: []string{"br-active"},
				Source:        "nft list ruleset",
			}},
		},
		Runtimes: availableRuntimeInventory(),
	}

	if leaks := DetectStaleFirewallRules(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 for present interface: %#v", len(leaks), leaks)
	}
}

func TestDetectStaleFirewallRulesSkipsWildcardWithMatchingInterface(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{
			NetworkInterfaces: []inspect.NetworkInterface{{Name: "br-active123"}},
			FirewallRules: []inspect.FirewallRule{{
				Backend:       "iptables",
				Table:         "filter",
				Chain:         "FORWARD",
				Raw:           "-A FORWARD -o br-active+ -j ACCEPT",
				InterfaceRefs: []string{"br-active+"},
				Source:        "iptables-save",
			}},
		},
		Runtimes: availableRuntimeInventory(),
	}

	if leaks := DetectStaleFirewallRules(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 for matching wildcard: %#v", len(leaks), leaks)
	}
}

func TestDetectStaleFirewallRulesDetectsMissingWildcardInterface(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{
			NetworkInterfaces: []inspect.NetworkInterface{{Name: "eth0"}},
			FirewallRules: []inspect.FirewallRule{{
				Backend:       "iptables",
				Table:         "filter",
				Chain:         "FORWARD",
				Raw:           "-A FORWARD -o br-gone+ -j ACCEPT",
				InterfaceRefs: []string{"br-gone+"},
				Source:        "iptables-save",
			}},
		},
		Runtimes: availableRuntimeInventory(),
	}

	if leaks := DetectStaleFirewallRules(input); len(leaks) != 1 {
		t.Fatalf("len(leaks) = %d, want 1 for missing wildcard: %#v", len(leaks), leaks)
	}
}

func TestDetectStaleFirewallRulesSkipsDefaultBridgeNames(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{FirewallRules: []inspect.FirewallRule{
			{Backend: "iptables", Table: "nat", Chain: "DOCKER", Raw: "-A DOCKER -i docker0 -j RETURN", InterfaceRefs: []string{"docker0"}, Source: "iptables-save"},
			{Backend: "iptables", Table: "nat", Chain: "CNI", Raw: "-A CNI -i cni0 -j RETURN", InterfaceRefs: []string{"cni0"}, Source: "iptables-save"},
			{Backend: "nftables", Table: "ip/nat", Chain: "podman", Raw: `iifname "podman0" return`, InterfaceRefs: []string{"podman0"}, Source: "nft list ruleset"},
		}},
		Runtimes: availableRuntimeInventory(),
	}

	if leaks := DetectStaleFirewallRules(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 for default bridges: %#v", len(leaks), leaks)
	}
}

func TestDetectStaleFirewallRulesSkipsNonRuntimeInterfaces(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{FirewallRules: []inspect.FirewallRule{{
			Backend:       "iptables",
			Table:         "filter",
			Chain:         "INPUT",
			Raw:           "-A INPUT -i eth9 -j ACCEPT",
			InterfaceRefs: []string{"eth9"},
			Source:        "iptables-save",
		}}},
		Runtimes: availableRuntimeInventory(),
	}

	if leaks := DetectStaleFirewallRules(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 for non-runtime interface: %#v", len(leaks), leaks)
	}
}

func TestDetectStaleFirewallRulesSkipsWithoutRuntimeInventory(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{FirewallRules: []inspect.FirewallRule{{
			Backend:       "iptables",
			Table:         "nat",
			Chain:         "CNI-HOSTPORT-DNAT",
			Raw:           "-A CNI-HOSTPORT-DNAT -i br-deadbeef -j RETURN",
			InterfaceRefs: []string{"br-deadbeef"},
			Source:        "iptables-save",
		}}},
		Runtimes: []runtimeinv.Inventory{{Runtime: runtimeinv.NameDocker}},
	}

	if leaks := DetectStaleFirewallRules(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 without runtime inventory: %#v", len(leaks), leaks)
	}
}
