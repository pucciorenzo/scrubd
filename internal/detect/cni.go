package detect

import (
	"scrubd/internal/inspect"
)

func DetectStaleCNIAllocations(input Input) []Leak {
	if !runtimeCorrelationAvailable(input.Runtimes) {
		return nil
	}
	if !runtimeInventoryComplete(input.Runtimes) {
		return nil
	}

	knownIDs := knownContainerIDs(input.Runtimes)
	var leaks []Leak
	for _, allocation := range input.Host.CNIAllocations {
		if !staleCNIAllocationCandidate(allocation, knownIDs) {
			continue
		}

		resource := allocation.Network + " " + allocation.IP
		leak := NewLeak(
			LeakTypeCNIAllocation,
			SeverityLow,
			resource,
			"CNI IPAM allocation is not correlated with a known runtime container",
		)
		leak.Evidence = []string{
			"network: " + allocation.Network,
			"ip: " + allocation.IP,
			"path: " + allocation.Path,
			"container id: " + allocation.ContainerID,
			"source: " + allocation.Source,
			"known container reference: none",
		}
		leak.SafeAction = "Review CNI and runtime metadata before removing the stale IPAM allocation."
		leak.RiskNotes = "Removing active CNI state can cause IP conflicts or disrupt pod/container networking; scrubd does not generate a direct CNI state cleanup command."
		leaks = append(leaks, leak)
	}
	return leaks
}

func staleCNIAllocationCandidate(allocation inspect.CNIAllocation, knownIDs []string) bool {
	if allocation.Network == "" || allocation.IP == "" || allocation.ContainerID == "" {
		return false
	}
	return !referencesAnyContainer(allocation.ContainerID, knownIDs)
}
