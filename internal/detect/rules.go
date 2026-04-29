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
	if !runtimeInventoryComplete(input.Runtimes) {
		return nil
	}

	visibleInterfaces := networkInterfaceIndexes(input.Host.NetworkInterfaces)
	var leaks []Leak
	for _, iface := range input.Host.NetworkInterfaces {
		if iface.Kind != "veth" {
			continue
		}
		if iface.PeerIndex != 0 {
			if _, ok := visibleInterfaces[iface.PeerIndex]; ok {
				continue
			}
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
			vethPeerEvidence(iface),
			"runtime inventories: all selected runtimes available",
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

func networkInterfaceIndexes(interfaces []inspect.NetworkInterface) map[int]struct{} {
	out := make(map[int]struct{}, len(interfaces))
	for _, iface := range interfaces {
		if iface.Index != 0 {
			out[iface.Index] = struct{}{}
		}
	}
	return out
}

func vethPeerEvidence(iface inspect.NetworkInterface) string {
	if iface.PeerIndex == 0 {
		return "peer interface index: unknown"
	}
	return fmt.Sprintf("peer interface index: %d not visible on host", iface.PeerIndex)
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
		if ns.Inode == "" {
			continue
		}
		if _, ok := processInodes[ns.Inode]; ok {
			continue
		}

		leak := NewLeak(
			LeakTypeNetworkNS,
			SeverityMedium,
			ns.Path,
			"named network namespace has no matching process network namespace",
		)
		leak.Evidence = []string{
			fmt.Sprintf("namespace source: %s", ns.Source),
			fmt.Sprintf("namespace inode: %s", ns.Inode),
			"matching process namespace: none",
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
	if !runtimeCorrelationAvailable(input.Runtimes) {
		return nil
	}
	runningIDs := runningContainerIDs(input.Runtimes)
	knownIDs := knownContainerIDs(input.Runtimes)

	var leaks []Leak
	for _, mount := range input.Host.Mounts {
		if !containerMountCandidate(mount) {
			continue
		}
		if referencesAnyContainer(mountFingerprint(mount), knownIDs) {
			continue
		}
		if referencesAnyRunningContainer(mountFingerprint(mount), runningIDs) {
			continue
		}

		leak := NewLeak(
			LeakTypeMount,
			SeverityMedium,
			mount.MountPoint,
			"container runtime mount has no matching known container reference",
		)
		leak.Evidence = []string{
			fmt.Sprintf("mount id: %s", mount.ID),
			fmt.Sprintf("mount point: %s", mount.MountPoint),
			fmt.Sprintf("filesystem: %s", mount.FSType),
			fmt.Sprintf("source: %s", mount.Source),
			"known container reference: none",
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
	if !runtimeCorrelationAvailable(input.Runtimes) {
		return nil
	}
	runningIDs := runningContainerIDs(input.Runtimes)
	knownIDs := knownContainerIDs(input.Runtimes)

	var leaks []Leak
	for _, snapshot := range input.Host.Snapshots {
		if !overlaySnapshotCandidate(snapshot) {
			continue
		}
		if referencesAnyContainer(snapshot.Path, knownIDs) {
			continue
		}
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
			"overlay snapshot is not mounted and has no matching known container reference",
		)
		leak.Evidence = []string{
			fmt.Sprintf("runtime: %s", snapshot.Runtime),
			fmt.Sprintf("snapshot id: %s", snapshot.ID),
			fmt.Sprintf("path: %s", snapshot.Path),
			"mounted: false",
			"known container reference: none",
		}
		leak.SafeAction = fmt.Sprintf("%s runtime garbage collection or manual snapshot review", snapshot.Runtime)
		leak.RiskNotes = "snapshot directories can back images or stopped containers; do not remove directly without runtime metadata"
		leaks = append(leaks, leak)
	}
	return leaks
}

func DetectStaleCgroups(input Input) []Leak {
	if !runtimeCorrelationAvailable(input.Runtimes) {
		return nil
	}
	runningIDs := runningContainerIDs(input.Runtimes)
	knownIDs := knownContainerIDs(input.Runtimes)

	var leaks []Leak
	for _, cgroup := range input.Host.Cgroups {
		if !containerCgroupCandidate(cgroup.Path) {
			continue
		}
		if !cgroup.ProcessCountKnown || cgroup.ProcessCount != 0 {
			continue
		}
		if referencesAnyContainer(cgroup.Path, knownIDs) {
			continue
		}
		if referencesAnyRunningContainer(cgroup.Path, runningIDs) {
			continue
		}

		leak := NewLeak(
			LeakTypeCgroup,
			SeverityLow,
			cgroup.Path,
			"container runtime cgroup has no matching known container reference",
		)
		leak.Evidence = []string{
			fmt.Sprintf("hierarchy: %s", cgroup.HierarchyID),
			fmt.Sprintf("controllers: %s", strings.Join(cgroup.Controllers, ",")),
			fmt.Sprintf("process count: %d", cgroup.ProcessCount),
			"known container reference: none",
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
	if !runtimeCorrelationAvailable(input.Runtimes) {
		return nil
	}
	runningIDs := runningContainerIDs(input.Runtimes)
	knownIDs := knownContainerIDs(input.Runtimes)

	var leaks []Leak
	for _, process := range input.Host.Processes {
		if !runtimeProcessCandidate(process, input.Runtimes) {
			continue
		}
		if referencesAnyContainer(processFingerprint(process), knownIDs) {
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
			"container runtime helper process has no matching known container reference",
		)
		leak.Evidence = []string{
			fmt.Sprintf("pid: %d", process.PID),
			fmt.Sprintf("command: %s", process.Command),
			fmt.Sprintf("args: %s", strings.Join(process.Args, " ")),
			"known container reference: none",
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

func runtimeCorrelationAvailable(inventories []runtimeinv.Inventory) bool {
	for _, inv := range inventories {
		if inv.Available || len(inv.Containers) > 0 {
			return true
		}
	}
	return false
}

func runtimeInventoryComplete(inventories []runtimeinv.Inventory) bool {
	if len(inventories) == 0 {
		return false
	}
	for _, inv := range inventories {
		if !inv.Available {
			return false
		}
	}
	return true
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

func knownContainerIDs(inventories []runtimeinv.Inventory) []string {
	var ids []string
	for _, inv := range inventories {
		for _, container := range inv.Containers {
			if container.ID != "" {
				ids = append(ids, container.ID)
			}
		}
	}
	return ids
}

func containerMountCandidate(mount inspect.Mount) bool {
	return dockerOverlayMountCandidate(mount.MountPoint) ||
		containerdOverlayMountCandidate(mount.MountPoint)
}

func dockerOverlayMountCandidate(path string) bool {
	return pathHasSegment(path, "overlay2") && pathLastSegment(path) == "merged"
}

func containerdOverlayMountCandidate(path string) bool {
	return pathHasSegment(path, "io.containerd.snapshotter.v1.overlayfs") &&
		pathHasSegment(path, "snapshots") &&
		pathLastSegment(path) == "fs"
}

func overlaySnapshotCandidate(snapshot inspect.Snapshot) bool {
	switch snapshot.Runtime {
	case "docker":
		return pathHasSegment(snapshot.Path, "overlay2")
	case "containerd":
		return pathHasSegment(snapshot.Path, "io.containerd.snapshotter.v1.overlayfs") &&
			pathHasSegment(snapshot.Path, "snapshots")
	default:
		return false
	}
}

func containerCgroupCandidate(path string) bool {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".service") || strings.HasSuffix(lower, ".socket") {
		return false
	}
	segments := pathSegments(lower)
	if pathHasSegment(lower, "kubepods") || pathHasSegment(lower, "kubepods.slice") || pathHasSegmentPrefix(lower, "kubepods-") {
		for _, segment := range segments {
			if strings.HasPrefix(segment, "pod") {
				return true
			}
		}
		return false
	}
	for _, segment := range segments {
		if runtimeCgroupSegment(segment) {
			return true
		}
	}
	return false
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

func runtimeProcessCandidate(process inspect.Process, runtimes []runtimeinv.Inventory) bool {
	command := strings.ToLower(process.Command)
	for _, inv := range runtimes {
		if !inv.Available && len(inv.Containers) == 0 {
			continue
		}
		switch inv.Runtime {
		case runtimeinv.NameDocker:
			if strings.Contains(command, "docker-proxy") || dockerRuncProcess(process) {
				return true
			}
		case runtimeinv.NameContainerd:
			if strings.Contains(command, "containerd-shim") || containerdRuncProcess(process) {
				return true
			}
		}
	}
	return false
}

func processFingerprint(process inspect.Process) string {
	parts := append([]string{process.Command}, process.Args...)
	return strings.Join(parts, " ")
}

func snapshotMounted(snapshot inspect.Snapshot, mounts []inspect.Mount) bool {
	for _, mount := range mounts {
		if pathHasPrefixBoundary(mount.MountPoint, snapshot.Path) ||
			pathHasPrefixBoundary(mount.Root, snapshot.Path) ||
			pathHasPrefixBoundary(mount.Source, snapshot.Path) ||
			mountOptionsReferencePath(mount.Options, snapshot.Path) ||
			mountOptionsReferencePath(mount.SuperOpts, snapshot.Path) {
			return true
		}
	}
	return false
}

func referencesAnyRunningContainer(value string, ids []string) bool {
	return referencesAnyContainer(value, ids)
}

func referencesAnyContainer(value string, ids []string) bool {
	for _, id := range ids {
		if strings.Contains(value, id) {
			return true
		}
	}
	return false
}

func runtimeCgroupSegment(segment string) bool {
	switch {
	case segment == "docker", segment == "containerd", segment == "libpod":
		return true
	case strings.HasPrefix(segment, "docker-") && strings.HasSuffix(segment, ".scope"):
		return true
	case strings.HasPrefix(segment, "containerd-") && strings.HasSuffix(segment, ".scope"):
		return true
	case strings.HasPrefix(segment, "libpod-") && strings.HasSuffix(segment, ".scope"):
		return true
	default:
		return false
	}
}

func dockerRuncProcess(process inspect.Process) bool {
	return runcProcessWithContext(process, "docker")
}

func containerdRuncProcess(process inspect.Process) bool {
	return runcProcessWithContext(process, "containerd")
}

func runcProcessWithContext(process inspect.Process, runtimeName string) bool {
	if strings.ToLower(process.Command) != "runc" {
		return false
	}
	fingerprint := strings.ToLower(processFingerprint(process))
	return strings.Contains(fingerprint, runtimeName)
}

func mountOptionsReferencePath(options []string, path string) bool {
	for _, option := range options {
		for _, value := range strings.Split(option, ":") {
			if keyEnd := strings.IndexByte(value, '='); keyEnd >= 0 {
				value = value[keyEnd+1:]
			}
			if pathHasPrefixBoundary(value, path) {
				return true
			}
		}
	}
	return false
}

func pathSegments(path string) []string {
	parts := strings.Split(strings.ToLower(path), "/")
	segments := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			segments = append(segments, part)
		}
	}
	return segments
}

func pathHasSegment(path, segment string) bool {
	segment = strings.ToLower(segment)
	for _, item := range pathSegments(path) {
		if item == segment {
			return true
		}
	}
	return false
}

func pathHasSegmentPrefix(path, prefix string) bool {
	prefix = strings.ToLower(prefix)
	for _, item := range pathSegments(path) {
		if strings.HasPrefix(item, prefix) {
			return true
		}
	}
	return false
}

func pathLastSegment(path string) string {
	segments := pathSegments(path)
	if len(segments) == 0 {
		return ""
	}
	return segments[len(segments)-1]
}

func pathHasPrefixBoundary(path, prefix string) bool {
	path = strings.TrimRight(strings.ToLower(strings.TrimSpace(path)), "/")
	prefix = strings.TrimRight(strings.ToLower(strings.TrimSpace(prefix)), "/")
	if path == "" || prefix == "" {
		return false
	}
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

func nsName(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
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
