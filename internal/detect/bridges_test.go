package detect

import (
	"testing"

	"scrubd/internal/inspect"
	runtimeinv "scrubd/internal/runtime"
)

func TestDetectStaleNetworkBridges(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{NetworkInterfaces: []inspect.NetworkInterface{
			{Name: "lo", Index: 1, Kind: "unknown"},
			{Name: "br-deadbeef", Index: 2, Kind: "bridge", BridgePortsKnown: true, Flags: []string{"broadcast", "multicast"}},
		}},
		Runtimes: []runtimeinv.Inventory{{Runtime: runtimeinv.NameDocker, Available: true}},
	}

	leaks := DetectStaleNetworkBridges(input)
	if len(leaks) != 1 {
		t.Fatalf("len(leaks) = %d, want 1", len(leaks))
	}
	if leaks[0].Type != LeakTypeNetworkBridge || leaks[0].Resource != "br-deadbeef" {
		t.Fatalf("unexpected leak: %#v", leaks[0])
	}
	if len(leaks[0].CleanupPlan) != 0 {
		t.Fatalf("cleanup plan = %#v, want none for bridge finding", leaks[0].CleanupPlan)
	}
	if !hasEvidence(leaks[0], "bridge ports: 0") {
		t.Fatalf("evidence = %#v, want bridge port evidence", leaks[0].Evidence)
	}
}

func TestDetectStaleNetworkBridgesSkipsDefaultBridgeNames(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{NetworkInterfaces: []inspect.NetworkInterface{
			{Name: "docker0", Index: 2, Kind: "bridge"},
			{Name: "cni0", Index: 3, Kind: "bridge"},
			{Name: "podman0", Index: 4, Kind: "bridge"},
		}},
		Runtimes: []runtimeinv.Inventory{{Runtime: runtimeinv.NameDocker, Available: true}},
	}

	if leaks := DetectStaleNetworkBridges(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 for default bridge names: %#v", len(leaks), leaks)
	}
}

func TestDetectStaleNetworkBridgesSkipsBridgeWithPorts(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{NetworkInterfaces: []inspect.NetworkInterface{{
			Name:             "br-active",
			Index:            2,
			Kind:             "bridge",
			BridgePorts:      []string{"veth0"},
			BridgePortsKnown: true,
		}}},
		Runtimes: []runtimeinv.Inventory{{Runtime: runtimeinv.NameDocker, Available: true}},
	}

	if leaks := DetectStaleNetworkBridges(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 for bridge with ports: %#v", len(leaks), leaks)
	}
}

func TestDetectStaleNetworkBridgesSkipsWithRunningContainers(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{NetworkInterfaces: []inspect.NetworkInterface{{
			Name:             "br-deadbeef",
			Index:            2,
			Kind:             "bridge",
			BridgePortsKnown: true,
		}}},
		Runtimes: []runtimeinv.Inventory{{
			Runtime:   runtimeinv.NameDocker,
			Available: true,
			Containers: []runtimeinv.Container{{
				ID:    "abc123",
				State: "running",
			}},
		}},
	}

	if leaks := DetectStaleNetworkBridges(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 with running containers: %#v", len(leaks), leaks)
	}
}

func TestDetectStaleNetworkBridgesSkipsWhenRuntimeInventoryIncomplete(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{NetworkInterfaces: []inspect.NetworkInterface{{
			Name:             "br-deadbeef",
			Index:            2,
			Kind:             "bridge",
			BridgePortsKnown: true,
		}}},
		Runtimes: []runtimeinv.Inventory{
			{Runtime: runtimeinv.NameDocker, Available: true},
			{Runtime: runtimeinv.NameContainerd},
		},
	}

	if leaks := DetectStaleNetworkBridges(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 with incomplete runtime inventory: %#v", len(leaks), leaks)
	}
}

func TestDetectStaleNetworkBridgesSkipsUnknownBridgePorts(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{NetworkInterfaces: []inspect.NetworkInterface{{
			Name:  "br-deadbeef",
			Index: 2,
			Kind:  "bridge",
		}}},
		Runtimes: []runtimeinv.Inventory{{Runtime: runtimeinv.NameDocker, Available: true}},
	}

	if leaks := DetectStaleNetworkBridges(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 when bridge port inventory is unknown: %#v", len(leaks), leaks)
	}
}
