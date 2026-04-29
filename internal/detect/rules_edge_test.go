package detect

import (
	"testing"

	"scrubd/internal/inspect"
	runtimeinv "scrubd/internal/runtime"
)

func TestDetectOrphanVethEdgeCases(t *testing.T) {
	tests := []struct {
		name         string
		input        Input
		wantLeaks    int
		wantEvidence string
	}{
		{
			name: "detects veth with unknown peer index",
			input: Input{
				Host: inspect.Inventory{NetworkInterfaces: []inspect.NetworkInterface{
					{Name: "vethunknown", Index: 2, Kind: "veth"},
				}},
				Runtimes: availableRuntimeInventory(),
			},
			wantLeaks:    1,
			wantEvidence: "peer interface index: unknown",
		},
		{
			name: "skips non-veth interfaces",
			input: Input{
				Host: inspect.Inventory{NetworkInterfaces: []inspect.NetworkInterface{
					{Name: "eth0", Index: 2, Kind: "ether"},
				}},
				Runtimes: availableRuntimeInventory(),
			},
		},
		{
			name: "skips without selected runtime inventory",
			input: Input{
				Host: inspect.Inventory{NetworkInterfaces: []inspect.NetworkInterface{
					{Name: "vethunknown", Index: 2, Kind: "veth"},
				}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			leaks := DetectOrphanVeth(tt.input)
			if len(leaks) != tt.wantLeaks {
				t.Fatalf("len(leaks) = %d, want %d: %#v", len(leaks), tt.wantLeaks, leaks)
			}
			if tt.wantEvidence != "" && !hasEvidence(leaks[0], tt.wantEvidence) {
				t.Fatalf("evidence = %#v, want %q", leaks[0].Evidence, tt.wantEvidence)
			}
		})
	}
}

func TestDetectStaleNetworkNamespacesEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		host      inspect.Inventory
		wantLeaks int
	}{
		{
			name: "detects stale namespace among process-only namespaces",
			host: inspect.Inventory{NetworkNamespaces: []inspect.NetworkNamespace{
				{Path: "/proc/10/ns/net", Inode: "10", Source: "process", PID: 10},
				{Path: "/var/run/netns/stale", Inode: "11", Source: "netns"},
			}},
			wantLeaks: 1,
		},
		{
			name: "skips process namespace entries",
			host: inspect.Inventory{NetworkNamespaces: []inspect.NetworkNamespace{
				{Path: "/proc/10/ns/net", Inode: "10", Source: "process", PID: 10},
			}},
		},
		{
			name: "skips named namespace without inode even with process namespaces present",
			host: inspect.Inventory{NetworkNamespaces: []inspect.NetworkNamespace{
				{Path: "/var/run/netns/no-inode", Source: "netns"},
				{Path: "/proc/10/ns/net", Inode: "10", Source: "process", PID: 10},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			leaks := DetectStaleNetworkNamespaces(tt.host)
			if len(leaks) != tt.wantLeaks {
				t.Fatalf("len(leaks) = %d, want %d: %#v", len(leaks), tt.wantLeaks, leaks)
			}
		})
	}
}

func TestDetectAbandonedMountsEdgeCases(t *testing.T) {
	const id = "abcdef1234567890"
	tests := []struct {
		name      string
		input     Input
		wantLeaks int
	}{
		{
			name: "skips without runtime correlation",
			input: Input{Host: inspect.Inventory{Mounts: []inspect.Mount{{
				ID:         "42",
				MountPoint: "/var/lib/docker/overlay2/leaked/merged",
				FSType:     "overlay",
				Source:     "overlay",
			}}}},
		},
		{
			name: "skips known container reference in lowerdir option",
			input: Input{
				Host: inspect.Inventory{Mounts: []inspect.Mount{{
					ID:         "42",
					MountPoint: "/var/lib/docker/overlay2/leaked/merged",
					FSType:     "overlay",
					Source:     "overlay",
					SuperOpts:  []string{"lowerdir=/var/lib/docker/overlay2/" + id + "/diff"},
				}}},
				Runtimes: []runtimeinv.Inventory{{
					Runtime:   runtimeinv.NameDocker,
					Available: true,
					Containers: []runtimeinv.Container{{
						ID:    id,
						State: "exited",
					}},
				}},
			},
		},
		{
			name: "does not treat container id prefix sibling as referenced",
			input: Input{
				Host: inspect.Inventory{Mounts: []inspect.Mount{{
					ID:         "42",
					MountPoint: "/var/lib/docker/overlay2/" + id + "99/merged",
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
			},
			wantLeaks: 1,
		},
		{
			name: "detects containerd snapshot fs mount with docker-only inventory",
			input: Input{
				Host: inspect.Inventory{Mounts: []inspect.Mount{{
					ID:         "42",
					MountPoint: "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/12/fs",
					FSType:     "overlay",
					Source:     "overlay",
				}}},
				Runtimes: availableRuntimeInventory(),
			},
			wantLeaks: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			leaks := DetectAbandonedMounts(tt.input)
			if len(leaks) != tt.wantLeaks {
				t.Fatalf("len(leaks) = %d, want %d: %#v", len(leaks), tt.wantLeaks, leaks)
			}
		})
	}
}

func TestDetectDanglingOverlaySnapshotsEdgeCases(t *testing.T) {
	const path = "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/12"
	tests := []struct {
		name      string
		input     Input
		wantLeaks int
	}{
		{
			name: "skips without runtime correlation",
			input: Input{Host: inspect.Inventory{Snapshots: []inspect.Snapshot{{
				Runtime: "containerd",
				ID:      "12",
				Path:    path,
			}}}},
		},
		{
			name: "skips snapshot referenced by mount root",
			input: Input{
				Host: inspect.Inventory{
					Snapshots: []inspect.Snapshot{{Runtime: "containerd", ID: "12", Path: path}},
					Mounts:    []inspect.Mount{{Root: path + "/fs", FSType: "overlay", Source: "overlay"}},
				},
				Runtimes: availableRuntimeInventory(),
			},
		},
		{
			name: "skips snapshot referenced by mount source",
			input: Input{
				Host: inspect.Inventory{
					Snapshots: []inspect.Snapshot{{Runtime: "containerd", ID: "12", Path: path}},
					Mounts:    []inspect.Mount{{MountPoint: "/mnt/merged", FSType: "overlay", Source: path + "/fs"}},
				},
				Runtimes: availableRuntimeInventory(),
			},
		},
		{
			name: "skips snapshot referenced by normal mount option",
			input: Input{
				Host: inspect.Inventory{
					Snapshots: []inspect.Snapshot{{Runtime: "containerd", ID: "12", Path: path}},
					Mounts: []inspect.Mount{{
						MountPoint: "/mnt/merged",
						FSType:     "overlay",
						Source:     "overlay",
						Options:    []string{"workdir=" + path + "/work"},
					}},
				},
				Runtimes: availableRuntimeInventory(),
			},
		},
		{
			name: "detects docker overlay snapshot",
			input: Input{
				Host: inspect.Inventory{Snapshots: []inspect.Snapshot{{
					Runtime: "docker",
					ID:      "leaked",
					Path:    "/var/lib/docker/overlay2/leaked",
				}}},
				Runtimes: availableRuntimeInventory(),
			},
			wantLeaks: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			leaks := DetectDanglingOverlaySnapshots(tt.input)
			if len(leaks) != tt.wantLeaks {
				t.Fatalf("len(leaks) = %d, want %d: %#v", len(leaks), tt.wantLeaks, leaks)
			}
		})
	}
}

func TestDetectStaleCgroupsEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		input     Input
		wantLeaks int
	}{
		{
			name: "skips without runtime correlation",
			input: Input{Host: inspect.Inventory{Cgroups: []inspect.Cgroup{{
				HierarchyID:       "0",
				Path:              "/system.slice/docker-leaked.scope",
				ProcessCountKnown: true,
			}}}},
		},
		{
			name: "detects pod cgroup under kubepods",
			input: Input{
				Host: inspect.Inventory{Cgroups: []inspect.Cgroup{{
					HierarchyID:       "0",
					Path:              "/kubepods.slice/kubepods-burstable.slice/pod123",
					ProcessCountKnown: true,
				}}},
				Runtimes: availableRuntimeInventory(),
			},
			wantLeaks: 1,
		},
		{
			name: "detects libpod scope",
			input: Input{
				Host: inspect.Inventory{Cgroups: []inspect.Cgroup{{
					HierarchyID:       "0",
					Path:              "/machine.slice/libpod-leaked.scope",
					ProcessCountKnown: true,
				}}},
				Runtimes: availableRuntimeInventory(),
			},
			wantLeaks: 1,
		},
		{
			name: "skips non-service unit with runtime word only in parent",
			input: Input{
				Host: inspect.Inventory{Cgroups: []inspect.Cgroup{{
					HierarchyID:       "0",
					Path:              "/system.slice/docker-helper/worker.scope",
					ProcessCountKnown: true,
				}}},
				Runtimes: availableRuntimeInventory(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			leaks := DetectStaleCgroups(tt.input)
			if len(leaks) != tt.wantLeaks {
				t.Fatalf("len(leaks) = %d, want %d: %#v", len(leaks), tt.wantLeaks, leaks)
			}
		})
	}
}

func TestDetectOrphanRuntimeProcessesEdgeCases(t *testing.T) {
	const id = "abcdef1234567890"
	tests := []struct {
		name      string
		input     Input
		wantLeaks int
	}{
		{
			name: "skips without runtime correlation",
			input: Input{Host: inspect.Inventory{Processes: []inspect.Process{{
				PID:     123,
				Command: "containerd-shim-runc-v2",
				Args:    []string{"containerd-shim-runc-v2", "-id", "leaked"},
			}}}},
		},
		{
			name: "detects docker runc with docker context",
			input: Input{
				Host: inspect.Inventory{Processes: []inspect.Process{{
					PID:     123,
					Command: "runc",
					Args:    []string{"runc", "--root", "/run/docker/runtime-runc/moby", "state", "leaked"},
				}}},
				Runtimes: []runtimeinv.Inventory{{Runtime: runtimeinv.NameDocker, Available: true}},
			},
			wantLeaks: 1,
		},
		{
			name: "skips unavailable selected runtime",
			input: Input{
				Host: inspect.Inventory{Processes: []inspect.Process{{
					PID:     123,
					Command: "docker-proxy",
					Args:    []string{"docker-proxy", "-host-port", "8080"},
				}}},
				Runtimes: []runtimeinv.Inventory{{Runtime: runtimeinv.NameDocker}},
			},
		},
		{
			name: "skips known container reference in args",
			input: Input{
				Host: inspect.Inventory{Processes: []inspect.Process{{
					PID:     123,
					Command: "docker-proxy",
					Args:    []string{"docker-proxy", "-container-id", id},
				}}},
				Runtimes: []runtimeinv.Inventory{{
					Runtime:   runtimeinv.NameDocker,
					Available: true,
					Containers: []runtimeinv.Container{{
						ID:    id,
						State: "exited",
					}},
				}},
			},
		},
		{
			name: "detects podman conmon process",
			input: Input{
				Host: inspect.Inventory{Processes: []inspect.Process{{
					PID:     123,
					Command: "conmon",
					Args:    []string{"conmon", "--cid", "leaked"},
				}}},
				Runtimes: []runtimeinv.Inventory{{Runtime: runtimeinv.NamePodman, Available: true}},
			},
			wantLeaks: 1,
		},
		{
			name: "detects podman runc with libpod context",
			input: Input{
				Host: inspect.Inventory{Processes: []inspect.Process{{
					PID:     123,
					Command: "runc",
					Args:    []string{"runc", "--root", "/run/user/1000/libpod/runc", "state", "leaked"},
				}}},
				Runtimes: []runtimeinv.Inventory{{Runtime: runtimeinv.NamePodman, Available: true}},
			},
			wantLeaks: 1,
		},
		{
			name: "skips podman helper from unselected runtime",
			input: Input{
				Host: inspect.Inventory{Processes: []inspect.Process{{
					PID:     123,
					Command: "conmon",
					Args:    []string{"conmon", "--cid", "leaked"},
				}}},
				Runtimes: []runtimeinv.Inventory{{Runtime: runtimeinv.NameDocker, Available: true}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			leaks := DetectOrphanRuntimeProcesses(tt.input)
			if len(leaks) != tt.wantLeaks {
				t.Fatalf("len(leaks) = %d, want %d: %#v", len(leaks), tt.wantLeaks, leaks)
			}
		})
	}
}
