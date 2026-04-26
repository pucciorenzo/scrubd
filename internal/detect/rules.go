package detect

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"scrubd/internal/cleanup"
	"scrubd/internal/inspect"
	runtimeinv "scrubd/internal/runtime"
)

type Input struct {
	Host     inspect.Inventory      `json:"host"`
	Runtimes []runtimeinv.Inventory `json:"runtimes"`
}

func Detect(input Input) []Leak {
	var leaks []Leak
	leaks = append(leaks, DetectOrphanVeth(input)...)
	leaks = append(leaks, DetectStaleNetworkNamespaces(input.Host)...)
	leaks = append(leaks, DetectAbandonedMounts(input)...)
	leaks = append(leaks, DetectDanglingOverlaySnapshots(input)...)
	leaks = append(leaks, DetectStaleCgroups(input)...)
	leaks = append(leaks, DetectOrphanRuntimeProcesses(input)...)
	sortLeaks(leaks)
	return leaks
}

func DetectOrphanVeth(input Input) []Leak {
	if runningContainerCount(input.Runtimes) > 0 {
		return nil
	}

	var leaks []Leak
	for _, iface := range input.Host.NetworkInterfaces {
		if iface.Kind != "veth" {
			continue
		}

		leak := NewLeak(
			LeakTypeVethInterface,
			SeverityHigh,
			iface.Name,
			"veth interface found but no running runtime container references are available",
		)
		leak.Evidence = []string{
			fmt.Sprintf("interface index: %d", iface.Index),
			"interface kind: veth",
			"running containers: 0",
		}
		leak.SafeAction = fmt.Sprintf("ip link delete %s", iface.Name)
		leak.RiskNotes = "delete only after confirming no workload uses this interface"
		leak.CleanupPlan = []cleanup.Step{{
			Description: fmt.Sprintf("delete veth interface %s", iface.Name),
			Command:     []string{"ip", "link", "delete", iface.Name},
			Destructive: true,
		}}
		leaks = append(leaks, leak)
	}
	return leaks
}

func DetectStaleNetworkNamespaces(host inspect.Inventory) []Leak {
	processInodes := make(map[string]struct{})
	for _, ns := range host.NetworkNamespaces {
		if ns.Source == "process" && ns.Inode != "" {
			processInodes[ns.Inode] = struct{}{}
		}
	}

	var leaks []Leak
	for _, ns := range host.NetworkNamespaces {
		if ns.Source != "netns" {
			continue
		}
		if ns.Inode != "" {
			if _, ok := processInodes[ns.Inode]; ok {
				continue
			}
		}

		leak := NewLeak(
			LeakTypeNetworkNS,
			SeverityMedium,
			ns.Path,
			"named network namespace has no matching process network namespace",
		)
		leak.Evidence = []string{
			fmt.Sprintf("namespace source: %s", ns.Source),
			fmt.Sprintf("namespace inode: %s", emptyFallback(ns.Inode, "unknown")),
		}
		leak.SafeAction = fmt.Sprintf("ip netns delete %s", nsName(ns.Path))
		leak.RiskNotes = "delete only after confirming no CNI plugin or workload still owns this namespace"
		leak.CleanupPlan = []cleanup.Step{{
			Description: fmt.Sprintf("delete network namespace %s", nsName(ns.Path)),
			Command:     []string{"ip", "netns", "delete", nsName(ns.Path)},
			Destructive: true,
		}}
		leaks = append(leaks, leak)
	}
	return leaks
}

func DetectAbandonedMounts(input Input) []Leak {
	runningIDs := runningContainerIDs(input.Runtimes)

	var leaks []Leak
	for _, mount := range input.Host.Mounts {
		if !containerMountCandidate(mount) {
			continue
		}
		if referencesAnyRunningContainer(mountFingerprint(mount), runningIDs) {
			continue
		}

		leak := NewLeak(
			LeakTypeMount,
			SeverityMedium,
			mount.MountPoint,
			"container runtime mount has no matching running container reference",
		)
		leak.Evidence = []string{
			fmt.Sprintf("mount id: %s", mount.ID),
			fmt.Sprintf("filesystem: %s", mount.FSType),
			fmt.Sprintf("source: %s", mount.Source),
		}
		leak.SafeAction = fmt.Sprintf("umount %s", mount.MountPoint)
		leak.RiskNotes = "unmount only after confirming no runtime task or process still uses this mount"
		leak.CleanupPlan = []cleanup.Step{{
			Description: fmt.Sprintf("unmount %s", mount.MountPoint),
			Command:     []string{"umount", mount.MountPoint},
			Destructive: true,
		}}
		leaks = append(leaks, leak)
	}
	return leaks
}

func DetectDanglingOverlaySnapshots(input Input) []Leak {
	runningIDs := runningContainerIDs(input.Runtimes)

	var leaks []Leak
	for _, snapshot := range input.Host.Snapshots {
		if referencesAnyRunningContainer(snapshot.Path, runningIDs) {
			continue
		}
		if snapshotMounted(snapshot, input.Host.Mounts) {
			continue
		}

		leak := NewLeak(
			LeakTypeOverlaySnapshot,
			SeverityLow,
			snapshot.Path,
			"overlay snapshot is not mounted and has no matching running container reference",
		)
		leak.Evidence = []string{
			fmt.Sprintf("runtime: %s", snapshot.Runtime),
			fmt.Sprintf("snapshot id: %s", snapshot.ID),
		}
		leak.SafeAction = fmt.Sprintf("%s runtime garbage collection or manual snapshot review", snapshot.Runtime)
		leak.RiskNotes = "snapshot directories can back images or stopped containers; do not remove directly without runtime metadata"
		leaks = append(leaks, leak)
	}
	return leaks
}

func DetectStaleCgroups(input Input) []Leak {
	runningIDs := runningContainerIDs(input.Runtimes)

	var leaks []Leak
	for _, cgroup := range input.Host.Cgroups {
		if !containerCgroupCandidate(cgroup.Path) {
			continue
		}
		if referencesAnyRunningContainer(cgroup.Path, runningIDs) {
			continue
		}

		leak := NewLeak(
			LeakTypeCgroup,
			SeverityLow,
			cgroup.Path,
			"container runtime cgroup has no matching running container reference",
		)
		leak.Evidence = []string{
			fmt.Sprintf("hierarchy: %s", cgroup.HierarchyID),
			fmt.Sprintf("controllers: %s", strings.Join(cgroup.Controllers, ",")),
		}
		leak.SafeAction = fmt.Sprintf("rmdir /sys/fs/cgroup%s", cgroup.Path)
		leak.RiskNotes = "remove only after confirming the cgroup is empty and no runtime owns it"
		leak.CleanupPlan = []cleanup.Step{{
			Description: fmt.Sprintf("remove cgroup %s", cgroup.Path),
			Command:     []string{"rmdir", "/sys/fs/cgroup" + cgroup.Path},
			Destructive: true,
		}}
		leaks = append(leaks, leak)
	}
	return leaks
}

func DetectOrphanRuntimeProcesses(input Input) []Leak {
	runningIDs := runningContainerIDs(input.Runtimes)

	var leaks []Leak
	for _, process := range input.Host.Processes {
		if !runtimeProcessCandidate(process) {
			continue
		}
		if referencesAnyRunningContainer(processFingerprint(process), runningIDs) {
			continue
		}

		resource := strconv.Itoa(process.PID)
		leak := NewLeak(
			LeakTypeRuntimeProcess,
			SeverityMedium,
			resource,
			"container runtime helper process has no matching running container reference",
		)
		leak.Evidence = []string{
			fmt.Sprintf("pid: %d", process.PID),
			fmt.Sprintf("command: %s", process.Command),
			fmt.Sprintf("args: %s", strings.Join(process.Args, " ")),
		}
		leak.SafeAction = fmt.Sprintf("kill -TERM %d", process.PID)
		leak.RiskNotes = "terminate only after confirming the runtime no longer owns this process"
		leak.CleanupPlan = []cleanup.Step{{
			Description: fmt.Sprintf("terminate runtime helper process %d", process.PID),
			Command:     []string{"kill", "-TERM", resource},
			Destructive: true,
		}}
		leaks = append(leaks, leak)
	}
	return leaks
}

func runningContainerCount(inventories []runtimeinv.Inventory) int {
	var count int
	for _, inv := range inventories {
		for _, container := range inv.Containers {
			if container.State == "running" {
				count++
			}
		}
	}
	return count
}

func runningContainerIDs(inventories []runtimeinv.Inventory) []string {
	var ids []string
	for _, inv := range inventories {
		for _, container := range inv.Containers {
			if container.State == "running" && container.ID != "" {
				ids = append(ids, container.ID)
			}
		}
	}
	return ids
}

func containerMountCandidate(mount inspect.Mount) bool {
	fingerprint := mountFingerprint(mount)
	if !containsAny(fingerprint, "docker", "containerd", "containers", "kubepods") {
		return false
	}
	return mount.FSType == "overlay" ||
		containsAny(fingerprint, "/var/lib/docker", "/var/lib/containerd", "/run/containerd", "/run/docker")
}

func containerCgroupCandidate(path string) bool {
	return containsAny(path, "docker", "containerd", "kubepods", "libpod")
}

func mountFingerprint(mount inspect.Mount) string {
	parts := []string{
		mount.Root,
		mount.MountPoint,
		mount.FSType,
		mount.Source,
		strings.Join(mount.Options, ","),
		strings.Join(mount.SuperOpts, ","),
	}
	return strings.Join(parts, " ")
}

func runtimeProcessCandidate(process inspect.Process) bool {
	command := strings.ToLower(process.Command)
	return strings.Contains(command, "containerd-shim") ||
		strings.Contains(command, "docker-proxy") ||
		command == "runc"
}

func processFingerprint(process inspect.Process) string {
	parts := append([]string{process.Command}, process.Args...)
	return strings.Join(parts, " ")
}

func snapshotMounted(snapshot inspect.Snapshot, mounts []inspect.Mount) bool {
	for _, mount := range mounts {
		if strings.Contains(mountFingerprint(mount), snapshot.Path) {
			return true
		}
	}
	return false
}

func referencesAnyRunningContainer(value string, ids []string) bool {
	for _, id := range ids {
		if strings.Contains(value, id) {
			return true
		}
	}
	return false
}

func containsAny(value string, needles ...string) bool {
	value = strings.ToLower(value)
	for _, needle := range needles {
		if strings.Contains(value, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func nsName(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
}

func emptyFallback(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func sortLeaks(leaks []Leak) {
	sort.Slice(leaks, func(i, j int) bool {
		if leaks[i].Severity != leaks[j].Severity {
			return SeverityRank(leaks[i].Severity) > SeverityRank(leaks[j].Severity)
		}
		if leaks[i].Type != leaks[j].Type {
			return leaks[i].Type < leaks[j].Type
		}
		return leaks[i].Resource < leaks[j].Resource
	})
}
