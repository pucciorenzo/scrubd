package detect

import (
	"fmt"
	"strings"

	"scrubd/internal/cleanup"
)

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
