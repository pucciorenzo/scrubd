package detect

import (
	"scrubd/internal/inspect"
	runtimeinv "scrubd/internal/runtime"
)

func DetectStaleRuntimeStates(input Input) []Leak {
	if !runtimeCorrelationAvailable(input.Runtimes) {
		return nil
	}
	if !runtimeInventoryComplete(input.Runtimes) {
		return nil
	}

	knownIDs := knownContainerIDs(input.Runtimes)
	var leaks []Leak
	for _, state := range input.Host.RuntimeStates {
		if !staleRuntimeStateCandidate(state, knownIDs, input.Runtimes) {
			continue
		}

		leak := NewLeak(
			LeakTypeRuntimeState,
			SeverityLow,
			state.Path,
			"runtime state directory is not correlated with a known runtime container",
		)
		leak.Evidence = []string{
			"runtime: " + state.Runtime,
			"kind: " + state.Kind,
			"id: " + state.ID,
			"path: " + state.Path,
			"source: " + state.Source,
			"known container reference: none",
		}
		leak.SafeAction = "Review runtime metadata and use runtime-supported cleanup before removing stale runtime state."
		leak.RiskNotes = "Runtime state directories can be owned by active tasks or runtime metadata; scrubd does not generate a direct remove command."
		leaks = append(leaks, leak)
	}
	return leaks
}

func staleRuntimeStateCandidate(state inspect.RuntimeState, knownIDs []string, runtimes []runtimeinv.Inventory) bool {
	if state.Runtime == "" || state.Kind == "" || state.ID == "" || state.Path == "" {
		return false
	}
	if !runtimeSelected(state.Runtime, runtimes) {
		return false
	}
	return !referencesAnyContainer(state.ID, knownIDs)
}

func runtimeSelected(runtimeName string, runtimes []runtimeinv.Inventory) bool {
	for _, runtime := range runtimes {
		if string(runtime.Runtime) == runtimeName {
			return true
		}
	}
	return false
}
