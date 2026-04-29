package detect

import (
	"fmt"
	"strings"

	"scrubd/internal/inspect"
)

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
