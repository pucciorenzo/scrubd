package detect

import (
	"fmt"
	"strings"

	"scrubd/internal/cleanup"
	"scrubd/internal/inspect"
)

func DetectAbandonedMounts(input Input) []Leak {
	if !runtimeCorrelationAvailable(input.Runtimes) {
		return nil
	}

	knownIDs := knownContainerIDs(input.Runtimes)
	runningIDs := runningContainerIDs(input.Runtimes)

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
