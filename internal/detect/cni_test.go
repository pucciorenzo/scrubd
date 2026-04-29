package detect

import (
	"testing"

	"scrubd/internal/inspect"
	runtimeinv "scrubd/internal/runtime"
)

func TestDetectStaleCNIAllocations(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{CNIAllocations: []inspect.CNIAllocation{{
			Network:     "mynet",
			IP:          "10.88.0.2",
			Path:        "/var/lib/cni/networks/mynet/10.88.0.2",
			ContainerID: "abcdef1234567890",
			Source:      "cni_ipam",
		}}},
		Runtimes: []runtimeinv.Inventory{{Runtime: runtimeinv.NameDocker, Available: true}},
	}

	leaks := DetectStaleCNIAllocations(input)
	if len(leaks) != 1 {
		t.Fatalf("len(leaks) = %d, want 1", len(leaks))
	}
	if leaks[0].Type != LeakTypeCNIAllocation || leaks[0].Resource != "mynet 10.88.0.2" {
		t.Fatalf("unexpected leak: %#v", leaks[0])
	}
	if len(leaks[0].CleanupPlan) != 0 {
		t.Fatalf("cleanup plan = %#v, want none for CNI allocation", leaks[0].CleanupPlan)
	}
}

func TestDetectStaleCNIAllocationsSkipsKnownContainer(t *testing.T) {
	const id = "abcdef1234567890"
	input := Input{
		Host: inspect.Inventory{CNIAllocations: []inspect.CNIAllocation{{
			Network:     "mynet",
			IP:          "10.88.0.2",
			Path:        "/var/lib/cni/networks/mynet/10.88.0.2",
			ContainerID: id,
			Source:      "cni_ipam",
		}}},
		Runtimes: []runtimeinv.Inventory{{
			Runtime:   runtimeinv.NameDocker,
			Available: true,
			Containers: []runtimeinv.Container{{
				ID:    id,
				State: "exited",
			}},
		}},
	}

	if leaks := DetectStaleCNIAllocations(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 for known container: %#v", len(leaks), leaks)
	}
}

func TestDetectStaleCNIAllocationsSkipsIncompleteRuntimeInventory(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{CNIAllocations: []inspect.CNIAllocation{{
			Network:     "mynet",
			IP:          "10.88.0.2",
			Path:        "/var/lib/cni/networks/mynet/10.88.0.2",
			ContainerID: "abcdef1234567890",
			Source:      "cni_ipam",
		}}},
		Runtimes: []runtimeinv.Inventory{
			{Runtime: runtimeinv.NameDocker, Available: true},
			{Runtime: runtimeinv.NameContainerd},
		},
	}

	if leaks := DetectStaleCNIAllocations(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 with incomplete runtime inventory: %#v", len(leaks), leaks)
	}
}

func TestDetectStaleCNIAllocationsSkipsIncompleteAllocation(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{CNIAllocations: []inspect.CNIAllocation{{
			Network: "mynet",
			IP:      "10.88.0.2",
			Path:    "/var/lib/cni/networks/mynet/10.88.0.2",
			Source:  "cni_ipam",
		}}},
		Runtimes: []runtimeinv.Inventory{{Runtime: runtimeinv.NameDocker, Available: true}},
	}

	if leaks := DetectStaleCNIAllocations(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 for incomplete allocation: %#v", len(leaks), leaks)
	}
}
