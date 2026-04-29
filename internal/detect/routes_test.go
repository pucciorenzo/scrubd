package detect

import (
	"testing"

	"scrubd/internal/inspect"
	runtimeinv "scrubd/internal/runtime"
)

func TestDetectStaleRoutes(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{
			NetworkInterfaces: []inspect.NetworkInterface{{Name: "eth0"}},
			Routes: []inspect.Route{{
				Interface:   "br-deadbeef",
				Destination: "172.18.0.0",
				Mask:        "255.255.0.0",
				Gateway:     "0.0.0.0",
				Source:      "proc_net_route",
			}},
		},
		Runtimes: availableRuntimeInventory(),
	}

	leaks := DetectStaleRoutes(input)
	if len(leaks) != 1 {
		t.Fatalf("len(leaks) = %d, want 1", len(leaks))
	}
	if leaks[0].Type != LeakTypeRoute || leaks[0].Resource != "br-deadbeef 172.18.0.0/255.255.0.0" {
		t.Fatalf("unexpected leak: %#v", leaks[0])
	}
	if len(leaks[0].CleanupPlan) != 0 {
		t.Fatalf("cleanup plan = %#v, want none for route finding", leaks[0].CleanupPlan)
	}
}

func TestDetectStaleRoutesSkipsPresentInterface(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{
			NetworkInterfaces: []inspect.NetworkInterface{{Name: "br-active"}},
			Routes: []inspect.Route{{
				Interface:   "br-active",
				Destination: "172.18.0.0",
				Mask:        "255.255.0.0",
				Source:      "proc_net_route",
			}},
		},
		Runtimes: availableRuntimeInventory(),
	}

	if leaks := DetectStaleRoutes(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 for present interface: %#v", len(leaks), leaks)
	}
}

func TestDetectStaleRoutesSkipsDefaultBridgeNames(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{Routes: []inspect.Route{
			{Interface: "docker0", Destination: "172.17.0.0", Mask: "255.255.0.0", Source: "proc_net_route"},
			{Interface: "cni0", Destination: "10.88.0.0", Mask: "255.255.0.0", Source: "proc_net_route"},
			{Interface: "podman0", Destination: "10.89.0.0", Mask: "255.255.0.0", Source: "proc_net_route"},
		}},
		Runtimes: availableRuntimeInventory(),
	}

	if leaks := DetectStaleRoutes(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 for default bridges: %#v", len(leaks), leaks)
	}
}

func TestDetectStaleRoutesSkipsNonRuntimeInterfaces(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{Routes: []inspect.Route{{
			Interface:   "eth9",
			Destination: "192.168.99.0",
			Mask:        "255.255.255.0",
			Source:      "proc_net_route",
		}}},
		Runtimes: availableRuntimeInventory(),
	}

	if leaks := DetectStaleRoutes(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 for non-runtime interface: %#v", len(leaks), leaks)
	}
}

func TestDetectStaleRoutesSkipsWithoutRuntimeInventory(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{Routes: []inspect.Route{{
			Interface:   "br-deadbeef",
			Destination: "172.18.0.0",
			Mask:        "255.255.0.0",
			Source:      "proc_net_route",
		}}},
		Runtimes: []runtimeinv.Inventory{{Runtime: runtimeinv.NameDocker}},
	}

	if leaks := DetectStaleRoutes(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 without runtime inventory: %#v", len(leaks), leaks)
	}
}
