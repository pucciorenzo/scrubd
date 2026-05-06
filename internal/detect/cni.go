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

func DetectStaleCNIStateFiles(input Input) []Leak {
	if !runtimeCorrelationAvailable(input.Runtimes) {
		return nil
	}
	if !runtimeInventoryComplete(input.Runtimes) {
		return nil
	}

	knownIDs := knownContainerIDs(input.Runtimes)
	var leaks []Leak
	for _, state := range input.Host.CNIStateFiles {
		if !staleCNIStateFileCandidate(state, knownIDs) {
			continue
		}

		leak := NewLeak(
			LeakTypeCNIStateFile,
			SeverityLow,
			state.Path,
			"CNI state file is not correlated with a known runtime container",
		)
		leak.Evidence = []string{
			"kind: " + state.Kind,
			"network: " + state.Network,
			"path: " + state.Path,
			"container id: " + state.ContainerID,
			"source: " + state.Source,
			"known container reference: none",
		}
		leak.SafeAction = "Review CNI and runtime metadata before removing the stale CNI state file."
		leak.RiskNotes = "Removing active CNI cache state can confuse plugin bookkeeping or disrupt pod/container networking; scrubd does not generate a direct CNI state cleanup command."
		leaks = append(leaks, leak)
	}
	return leaks
}

func staleCNIStateFileCandidate(state inspect.CNIStateFile, knownIDs []string) bool {
	if state.Path == "" || state.ContainerID == "" {
		return false
	}
	return !referencesAnyContainer(state.ContainerID, knownIDs)
}
