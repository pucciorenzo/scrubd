package detect

import (
	"testing"

	"scrubd/internal/inspect"
	runtimeinv "scrubd/internal/runtime"
)

func TestDetectOrphanVeth(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{NetworkInterfaces: []inspect.NetworkInterface{
			{Name: "lo", Index: 1, Kind: "unknown"},
			{Name: "vethscrubd0", Index: 2, PeerIndex: 99, Kind: "veth"},
		}},
		Runtimes: []runtimeinv.Inventory{{Runtime: runtimeinv.NameDocker, Available: true}},
	}

	leaks := DetectOrphanVeth(input)
	if len(leaks) != 1 {
		t.Fatalf("len(leaks) = %d, want 1", len(leaks))
	}
	if leaks[0].Type != LeakTypeVethInterface || leaks[0].Resource != "vethscrubd0" {
		t.Fatalf("unexpected leak: %#v", leaks[0])
	}
	if len(leaks[0].CleanupPlan) != 1 || leaks[0].CleanupPlan[0].Command[0] != "ip" {
		t.Fatalf("missing cleanup plan: %#v", leaks[0].CleanupPlan)
	}
	if !hasEvidence(leaks[0], "peer interface index: 99 not visible on host") {
		t.Fatalf("evidence = %#v, want missing peer evidence", leaks[0].Evidence)
	}
}

func TestDetectOrphanVethSkipsVisiblePeerPair(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{NetworkInterfaces: []inspect.NetworkInterface{
			{Name: "veth-a", Index: 2, PeerIndex: 3, Kind: "veth"},
			{Name: "veth-b", Index: 3, PeerIndex: 2, Kind: "veth"},
		}},
		Runtimes: []runtimeinv.Inventory{{Runtime: runtimeinv.NameDocker, Available: true}},
	}

	if leaks := DetectOrphanVeth(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 for visible veth peer pair: %#v", len(leaks), leaks)
	}
}

func TestDetectOrphanVethSkipsWhenRuntimeHasRunningContainers(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{NetworkInterfaces: []inspect.NetworkInterface{
			{Name: "vethabc", Index: 2, Kind: "veth"},
		}},
		Runtimes: []runtimeinv.Inventory{{
			Runtime: runtimeinv.NameDocker,
			Containers: []runtimeinv.Container{{
				ID:    "abc",
				State: "running",
			}},
		}},
	}

	if leaks := DetectOrphanVeth(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0: %#v", len(leaks), leaks)
	}
}

func TestDetectOrphanVethSkipsWhenRuntimeInventoryIncomplete(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{NetworkInterfaces: []inspect.NetworkInterface{
			{Name: "vethabc", Index: 2, Kind: "veth"},
		}},
		Runtimes: []runtimeinv.Inventory{
			{Runtime: runtimeinv.NameDocker, Available: true},
			{Runtime: runtimeinv.NameContainerd, Available: false, Warnings: []string{"containerd missing"}},
		},
	}

	if leaks := DetectOrphanVeth(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 with incomplete runtime inventory: %#v", len(leaks), leaks)
	}
}

func TestDetectStaleNetworkNamespaces(t *testing.T) {
	host := inspect.Inventory{NetworkNamespaces: []inspect.NetworkNamespace{
		{Path: "/var/run/netns/scrubd-leak-ns", Inode: "10", Source: "netns"},
		{Path: "/proc/123/ns/net", Inode: "11", Source: "process", PID: 123},
	}}

	leaks := DetectStaleNetworkNamespaces(host)
	if len(leaks) != 1 {
		t.Fatalf("len(leaks) = %d, want 1", len(leaks))
	}
	if leaks[0].Type != LeakTypeNetworkNS || leaks[0].Resource != "/var/run/netns/scrubd-leak-ns" {
		t.Fatalf("unexpected leak: %#v", leaks[0])
	}
	if got := leaks[0].CleanupPlan[0].Command; len(got) != 4 || got[3] != "scrubd-leak-ns" {
		t.Fatalf("cleanup command = %#v", got)
	}
}

func TestDetectStaleNetworkNamespacesSkipsNamespaceReferencedByProcess(t *testing.T) {
	host := inspect.Inventory{NetworkNamespaces: []inspect.NetworkNamespace{
		{Path: "/var/run/netns/active", Inode: "10", Source: "netns"},
		{Path: "/proc/123/ns/net", Inode: "10", Source: "process", PID: 123},
	}}

	if leaks := DetectStaleNetworkNamespaces(host); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0: %#v", len(leaks), leaks)
	}
}

func TestDetectStaleNetworkNamespacesSkipsUnknownInode(t *testing.T) {
	host := inspect.Inventory{NetworkNamespaces: []inspect.NetworkNamespace{
		{Path: "/var/run/netns/unknown", Source: "netns"},
	}}

	if leaks := DetectStaleNetworkNamespaces(host); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 without namespace inode: %#v", len(leaks), leaks)
	}
}

func TestDetectAbandonedMounts(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{Mounts: []inspect.Mount{
			{
				ID:         "42",
				MountPoint: "/var/lib/docker/overlay2/leaked/merged",
				FSType:     "overlay",
				Source:     "overlay",
				SuperOpts:  []string{"lowerdir=/var/lib/docker/overlay2/leaked/l"},
			},
			{
				ID:         "43",
				MountPoint: "/home",
				FSType:     "ext4",
				Source:     "/dev/sda1",
			},
		}},
		Runtimes: []runtimeinv.Inventory{{Runtime: runtimeinv.NameContainerd, Available: true}},
	}

	leaks := DetectAbandonedMounts(input)
	if len(leaks) != 1 {
		t.Fatalf("len(leaks) = %d, want 1", len(leaks))
	}
	if leaks[0].Type != LeakTypeMount || leaks[0].Resource != "/var/lib/docker/overlay2/leaked/merged" {
		t.Fatalf("unexpected leak: %#v", leaks[0])
	}
	if !hasEvidence(leaks[0], "known container reference: none") {
		t.Fatalf("evidence = %#v, want missing known-container evidence", leaks[0].Evidence)
	}
	if got := leaks[0].CleanupPlan[0].Command; len(got) != 2 || got[0] != "umount" {
		t.Fatalf("cleanup command = %#v", got)
	}
}

func TestDetectOrphanRuntimeProcessesSkipsOtherRuntimeHelpers(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{Processes: []inspect.Process{{
			PID:     123,
			Command: "containerd-shim-runc-v2",
			Args:    []string{"containerd-shim-runc-v2", "-id", "leaked"},
		}}},
		Runtimes: []runtimeinv.Inventory{{Runtime: runtimeinv.NameDocker, Available: true}},
	}

	if leaks := DetectOrphanRuntimeProcesses(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 for helper from unselected runtime: %#v", len(leaks), leaks)
	}
}

func TestDetectOrphanRuntimeProcessesDetectsDockerProxy(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{Processes: []inspect.Process{{
			PID:     123,
			Command: "docker-proxy",
			Args:    []string{"docker-proxy", "-host-port", "8080"},
		}}},
		Runtimes: []runtimeinv.Inventory{{Runtime: runtimeinv.NameDocker, Available: true}},
	}

	if leaks := DetectOrphanRuntimeProcesses(input); len(leaks) != 1 {
		t.Fatalf("len(leaks) = %d, want 1 docker-proxy leak: %#v", len(leaks), leaks)
	}
}

func TestDetectAbandonedMountsDetectsContainerdSnapshotMount(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{Mounts: []inspect.Mount{{
			ID:         "42",
			MountPoint: "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/12/fs",
			FSType:     "overlay",
			Source:     "overlay",
		}}},
		Runtimes: []runtimeinv.Inventory{
			{Runtime: runtimeinv.NameDocker, Available: true},
			{Runtime: runtimeinv.NameContainerd, Available: true},
		},
	}

	leaks := DetectAbandonedMounts(input)
	if len(leaks) != 1 {
		t.Fatalf("len(leaks) = %d, want 1", len(leaks))
	}
}

func TestDetectAbandonedMountsSkipsBroadRuntimeDirectoryMount(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{Mounts: []inspect.Mount{{
			ID:         "42",
			MountPoint: "/var/lib/docker",
			FSType:     "tmpfs",
			Source:     "tmpfs",
		}}},
		Runtimes: availableRuntimeInventory(),
	}

	if leaks := DetectAbandonedMounts(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 for broad runtime directory mount: %#v", len(leaks), leaks)
	}
}

func TestDetectAbandonedMountsSkipsRunningContainerReference(t *testing.T) {
	const id = "abcdef1234567890"
	input := Input{
		Host: inspect.Inventory{Mounts: []inspect.Mount{{
			ID:         "42",
			MountPoint: "/var/lib/docker/overlay2/" + id + "/merged",
			FSType:     "overlay",
			Source:     "overlay",
		}}},
		Runtimes: []runtimeinv.Inventory{{
			Runtime: runtimeinv.NameDocker,
			Containers: []runtimeinv.Container{{
				ID:    id,
				State: "running",
			}},
		}},
	}

	if leaks := DetectAbandonedMounts(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0: %#v", len(leaks), leaks)
	}
}

func TestDetectAbandonedMountsSkipsStoppedContainerReference(t *testing.T) {
	const id = "abcdef1234567890"
	input := Input{
		Host: inspect.Inventory{Mounts: []inspect.Mount{{
			ID:         "42",
			MountPoint: "/var/lib/docker/overlay2/" + id + "/merged",
			FSType:     "overlay",
			Source:     "overlay",
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

	if leaks := DetectAbandonedMounts(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0: %#v", len(leaks), leaks)
	}
}

func TestDetectDanglingOverlaySnapshots(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{
			Snapshots: []inspect.Snapshot{{
				Runtime: "containerd",
				ID:      "12",
				Path:    "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/12",
			}},
		},
		Runtimes: availableRuntimeInventory(),
	}

	leaks := DetectDanglingOverlaySnapshots(input)
	if len(leaks) != 1 {
		t.Fatalf("len(leaks) = %d, want 1", len(leaks))
	}
	if leaks[0].Type != LeakTypeOverlaySnapshot || leaks[0].Severity != SeverityLow {
		t.Fatalf("unexpected leak: %#v", leaks[0])
	}
	if !hasEvidence(leaks[0], "mounted: false") || !hasEvidence(leaks[0], "known container reference: none") {
		t.Fatalf("evidence = %#v, want mount and known-container evidence", leaks[0].Evidence)
	}
	if len(leaks[0].CleanupPlan) != 0 {
		t.Fatalf("cleanup plan = %#v, want none", leaks[0].CleanupPlan)
	}
}

func TestDetectDanglingOverlaySnapshotsSkipsUnknownRuntime(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{Snapshots: []inspect.Snapshot{{
			Runtime: "unknown",
			ID:      "12",
			Path:    "/some/runtime/snapshots/12",
		}}},
		Runtimes: availableRuntimeInventory(),
	}

	if leaks := DetectDanglingOverlaySnapshots(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 for unknown snapshot runtime: %#v", len(leaks), leaks)
	}
}

func TestDetectDanglingOverlaySnapshotsSkipsMountedSnapshot(t *testing.T) {
	path := "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/12"
	input := Input{
		Host: inspect.Inventory{
			Snapshots: []inspect.Snapshot{{Runtime: "containerd", ID: "12", Path: path}},
			Mounts: []inspect.Mount{{
				MountPoint: path + "/fs",
				FSType:     "overlay",
				Source:     "overlay",
			}},
		},
		Runtimes: availableRuntimeInventory(),
	}

	if leaks := DetectDanglingOverlaySnapshots(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0: %#v", len(leaks), leaks)
	}
}

func TestDetectDanglingOverlaySnapshotsSkipsRunningContainerReference(t *testing.T) {
	const id = "abcdef1234567890"
	input := Input{
		Host: inspect.Inventory{Snapshots: []inspect.Snapshot{{
			Runtime: "docker",
			ID:      id,
			Path:    "/var/lib/docker/overlay2/" + id,
		}}},
		Runtimes: []runtimeinv.Inventory{{
			Runtime: runtimeinv.NameDocker,
			Containers: []runtimeinv.Container{{
				ID:    id,
				State: "running",
			}},
		}},
	}

	if leaks := DetectDanglingOverlaySnapshots(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0: %#v", len(leaks), leaks)
	}
}

func TestDetectDanglingOverlaySnapshotsSkipsStoppedContainerReference(t *testing.T) {
	const id = "abcdef1234567890"
	input := Input{
		Host: inspect.Inventory{Snapshots: []inspect.Snapshot{{
			Runtime: "docker",
			ID:      id,
			Path:    "/var/lib/docker/overlay2/" + id,
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

	if leaks := DetectDanglingOverlaySnapshots(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0: %#v", len(leaks), leaks)
	}
}

func TestDetectStaleCgroups(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{Cgroups: []inspect.Cgroup{
			{HierarchyID: "0", Controllers: []string{"memory"}, Path: "/system.slice/docker-leaked.scope", ProcessCountKnown: true},
			{HierarchyID: "0", Controllers: []string{"memory"}, Path: "/user.slice/user-501.slice", ProcessCountKnown: true},
		}},
		Runtimes: availableRuntimeInventory(),
	}

	leaks := DetectStaleCgroups(input)
	if len(leaks) != 1 {
		t.Fatalf("len(leaks) = %d, want 1", len(leaks))
	}
	if leaks[0].Type != LeakTypeCgroup || leaks[0].Resource != "/system.slice/docker-leaked.scope" {
		t.Fatalf("unexpected leak: %#v", leaks[0])
	}
	if !hasEvidence(leaks[0], "known container reference: none") {
		t.Fatalf("evidence = %#v, want missing known-container evidence", leaks[0].Evidence)
	}
	if !hasEvidence(leaks[0], "process count: 0") {
		t.Fatalf("evidence = %#v, want process count evidence", leaks[0].Evidence)
	}
	if got := leaks[0].CleanupPlan[0].Command; len(got) != 2 || got[0] != "rmdir" {
		t.Fatalf("cleanup command = %#v", got)
	}
}

func TestDetectStaleCgroupsSkipsNonEmptyCgroup(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{Cgroups: []inspect.Cgroup{{
			HierarchyID:       "0",
			Path:              "/system.slice/docker-leaked.scope",
			ProcessCountKnown: true,
			ProcessCount:      1,
		}}},
		Runtimes: availableRuntimeInventory(),
	}

	if leaks := DetectStaleCgroups(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 for non-empty cgroup: %#v", len(leaks), leaks)
	}
}

func TestDetectStaleCgroupsSkipsUnknownProcessCount(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{Cgroups: []inspect.Cgroup{{
			HierarchyID: "0",
			Path:        "/system.slice/docker-leaked.scope",
		}}},
		Runtimes: availableRuntimeInventory(),
	}

	if leaks := DetectStaleCgroups(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 without process count: %#v", len(leaks), leaks)
	}
}

func TestDetectStaleCgroupsSkipsRunningContainerReference(t *testing.T) {
	const id = "abcdef1234567890"
	input := Input{
		Host: inspect.Inventory{Cgroups: []inspect.Cgroup{{
			HierarchyID: "0",
			Path:        "/system.slice/docker-" + id + ".scope", ProcessCountKnown: true,
		}}},
		Runtimes: []runtimeinv.Inventory{{
			Runtime: runtimeinv.NameDocker,
			Containers: []runtimeinv.Container{{
				ID:    id,
				State: "running",
			}},
		}},
	}

	if leaks := DetectStaleCgroups(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0: %#v", len(leaks), leaks)
	}
}

func TestDetectStaleCgroupsSkipsStoppedContainerReference(t *testing.T) {
	const id = "abcdef1234567890"
	input := Input{
		Host: inspect.Inventory{Cgroups: []inspect.Cgroup{{
			HierarchyID: "0",
			Path:        "/system.slice/docker-" + id + ".scope", ProcessCountKnown: true,
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

	if leaks := DetectStaleCgroups(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0: %#v", len(leaks), leaks)
	}
}

func TestDetectStaleCgroupsSkipsGenericKubepodsParent(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{Cgroups: []inspect.Cgroup{
			{HierarchyID: "0", Path: "/kubepods.slice", ProcessCountKnown: true},
		}},
		Runtimes: availableRuntimeInventory(),
	}

	if leaks := DetectStaleCgroups(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0: %#v", len(leaks), leaks)
	}
}

func TestDetectStaleCgroupsSkipsRuntimeServiceUnits(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{Cgroups: []inspect.Cgroup{
			{HierarchyID: "0", Path: "/system.slice/containerd.service", ProcessCountKnown: true},
			{HierarchyID: "0", Path: "/system.slice/docker.service", ProcessCountKnown: true},
			{HierarchyID: "0", Path: "/system.slice/docker.socket", ProcessCountKnown: true},
		}},
		Runtimes: availableRuntimeInventory(),
	}

	if leaks := DetectStaleCgroups(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 for runtime service units: %#v", len(leaks), leaks)
	}
}

func TestDetectOrphanRuntimeProcesses(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{Processes: []inspect.Process{
			{PID: 123, Command: "containerd-shim-runc-v2", Args: []string{"containerd-shim-runc-v2", "-id", "leaked"}},
			{PID: 124, Command: "sshd", Args: []string{"sshd"}},
		}},
		Runtimes: []runtimeinv.Inventory{{Runtime: runtimeinv.NameContainerd, Available: true}},
	}

	leaks := DetectOrphanRuntimeProcesses(input)
	if len(leaks) != 1 {
		t.Fatalf("len(leaks) = %d, want 1", len(leaks))
	}
	if leaks[0].Type != LeakTypeRuntimeProcess || leaks[0].Resource != "123" {
		t.Fatalf("unexpected leak: %#v", leaks[0])
	}
	if !hasEvidence(leaks[0], "known container reference: none") {
		t.Fatalf("evidence = %#v, want missing known-container evidence", leaks[0].Evidence)
	}
	if got := leaks[0].CleanupPlan[0].Command; len(got) != 3 || got[0] != "kill" || got[2] != "123" {
		t.Fatalf("cleanup command = %#v", got)
	}
}

func TestDetectOrphanRuntimeProcessesSkipsRunningContainerReference(t *testing.T) {
	const id = "abcdef1234567890"
	input := Input{
		Host: inspect.Inventory{Processes: []inspect.Process{{
			PID:     123,
			Command: "containerd-shim-runc-v2",
			Args:    []string{"containerd-shim-runc-v2", "-id", id},
		}}},
		Runtimes: []runtimeinv.Inventory{{
			Runtime: runtimeinv.NameContainerd,
			Containers: []runtimeinv.Container{{
				ID:    id,
				State: "running",
			}},
		}},
	}

	if leaks := DetectOrphanRuntimeProcesses(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0: %#v", len(leaks), leaks)
	}
}

func TestDetectOrphanRuntimeProcessesSkipsStoppedContainerReference(t *testing.T) {
	const id = "abcdef1234567890"
	input := Input{
		Host: inspect.Inventory{Processes: []inspect.Process{{
			PID:     123,
			Command: "containerd-shim-runc-v2",
			Args:    []string{"containerd-shim-runc-v2", "-id", id},
		}}},
		Runtimes: []runtimeinv.Inventory{{
			Runtime:   runtimeinv.NameContainerd,
			Available: true,
			Containers: []runtimeinv.Container{{
				ID:    id,
				State: "exited",
			}},
		}},
	}

	if leaks := DetectOrphanRuntimeProcesses(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0: %#v", len(leaks), leaks)
	}
}

func TestDetectSortsLeaks(t *testing.T) {
	input := Input{
		Host: inspect.Inventory{
			NetworkInterfaces: []inspect.NetworkInterface{{Name: "vethb", Index: 2, Kind: "veth"}},
			NetworkNamespaces: []inspect.NetworkNamespace{{Path: "/var/run/netns/a", Inode: "9", Source: "netns"}},
			Mounts:            []inspect.Mount{{ID: "42", MountPoint: "/var/lib/docker/overlay2/leaked/merged", FSType: "overlay", Source: "overlay"}},
			Snapshots:         []inspect.Snapshot{{Runtime: "docker", ID: "snap", Path: "/var/lib/docker/overlay2/snap"}},
			Cgroups:           []inspect.Cgroup{{HierarchyID: "0", Path: "/system.slice/docker-leaked.scope", ProcessCountKnown: true}},
			Processes:         []inspect.Process{{PID: 123, Command: "containerd-shim-runc-v2", Args: []string{"containerd-shim-runc-v2", "-id", "leaked"}}},
		},
		Runtimes: []runtimeinv.Inventory{
			{Runtime: runtimeinv.NameDocker, Available: true},
			{Runtime: runtimeinv.NameContainerd, Available: true},
		},
	}

	leaks := Detect(input)
	if len(leaks) != 6 {
		t.Fatalf("len(leaks) = %d, want 6", len(leaks))
	}
	if leaks[0].Severity != SeverityHigh || leaks[5].Severity != SeverityLow {
		t.Fatalf("leaks not sorted by severity: %#v", leaks)
	}
}

func TestDetectSkipsRuntimeCorrelatedLeaksWithoutRuntimeInventory(t *testing.T) {
	input := Input{Host: inspect.Inventory{
		NetworkInterfaces: []inspect.NetworkInterface{{Name: "vethb", Index: 2, Kind: "veth"}},
		Mounts:            []inspect.Mount{{ID: "42", MountPoint: "/var/lib/docker/overlay2/leaked/merged", FSType: "overlay", Source: "overlay"}},
		Snapshots:         []inspect.Snapshot{{Runtime: "docker", ID: "snap", Path: "/var/lib/docker/overlay2/snap"}},
		Cgroups:           []inspect.Cgroup{{HierarchyID: "0", Path: "/system.slice/docker-leaked.scope"}},
		Processes:         []inspect.Process{{PID: 123, Command: "containerd-shim-runc-v2", Args: []string{"containerd-shim-runc-v2", "-id", "leaked"}}},
	}}

	if leaks := Detect(input); len(leaks) != 0 {
		t.Fatalf("len(leaks) = %d, want 0 without runtime inventory: %#v", len(leaks), leaks)
	}
}

func availableRuntimeInventory() []runtimeinv.Inventory {
	return []runtimeinv.Inventory{{Runtime: runtimeinv.NameDocker, Available: true}}
}

func hasEvidence(leak Leak, want string) bool {
	for _, evidence := range leak.Evidence {
		if evidence == want {
			return true
		}
	}
	return false
}
