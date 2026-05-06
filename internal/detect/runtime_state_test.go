package detect

import (
	"testing"

	"scrubd/internal/inspect"
	runtimeinv "scrubd/internal/runtime"
)

func TestDetectStaleRuntimeStates(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{RuntimeStates: []inspect.RuntimeState{{
			Runtime: "containerd",
			Kind:    "containerd_task",
			ID:      "abcdef1234567890",
			Path:    "/run/containerd/io.containerd.runtime.v2.task/k8s.io/abcdef1234567890",
			Source:  "runtime_state",
		}}},
		Runtimes: []runtimeinv.Inventory{{Runtime: runtimeinv.NameContainerd, Available: true}},
	}

	leaks := DetectStaleRuntimeStates(input)
	if len(leaks) != 1 {
		t.Fatalf("len(leaks) = %d, want 1", len(leaks))
	}
	if leaks[0].Type != LeakTypeRuntimeState || leaks[0].Resource != "/run/containerd/io.containerd.runtime.v2.task/k8s.io/abcdef1234567890" {
		t.Fatalf("unexpected leak: %#v", leaks[0])
	}
	if len(leaks[0].CleanupPlan) != 0 {
		t.Fatalf("cleanup plan = %#v, want none for runtime state", leaks[0].CleanupPlan)
	}
}

func TestDetectStaleRuntimeStatesSkipsKnownContainer(t *testing.T) {
	const id = "abcdef1234567890"
	input := Input{
		Host: inspect.Inventory{RuntimeStates: []inspect.RuntimeState{{
			Runtime: "docker",
			Kind:    "runc_bundle",
			ID:      id,
			Path:    "/run/docker/runtime-runc/moby/" + id,
			Source:  "runtime_state",
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

	if leaks := DetectStaleRuntimeStates(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 for known container: %#v", len(leaks), leaks)
	}
}

func TestDetectStaleRuntimeStatesSkipsIncompleteRuntimeInventory(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{RuntimeStates: []inspect.RuntimeState{{
			Runtime: "containerd",
			Kind:    "containerd_task",
			ID:      "abcdef1234567890",
			Path:    "/run/containerd/io.containerd.runtime.v2.task/k8s.io/abcdef1234567890",
			Source:  "runtime_state",
		}}},
		Runtimes: []runtimeinv.Inventory{
			{Runtime: runtimeinv.NameDocker, Available: true},
			{Runtime: runtimeinv.NameContainerd},
		},
	}

	if leaks := DetectStaleRuntimeStates(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 with incomplete runtime inventory: %#v", len(leaks), leaks)
	}
}

func TestDetectStaleRuntimeStatesSkipsUnselectedRuntime(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{RuntimeStates: []inspect.RuntimeState{{
			Runtime: "containerd",
			Kind:    "containerd_task",
			ID:      "abcdef1234567890",
			Path:    "/run/containerd/io.containerd.runtime.v2.task/k8s.io/abcdef1234567890",
			Source:  "runtime_state",
		}}},
		Runtimes: []runtimeinv.Inventory{{Runtime: runtimeinv.NameDocker, Available: true}},
	}

	if leaks := DetectStaleRuntimeStates(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 for unselected runtime: %#v", len(leaks), leaks)
	}
}
