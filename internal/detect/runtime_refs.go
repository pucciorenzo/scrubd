package detect

import (
	"strings"

	runtimeinv "scrubd/internal/runtime"
)

func runningContainerCount(runtimes []runtimeinv.Inventory) int {
	count := 0
	for _, runtime := range runtimes {
		for _, container := range runtime.Containers {
			if container.State == "running" {
				count++
			}
		}
	}
	return count
}

func runtimeCorrelationAvailable(runtimes []runtimeinv.Inventory) bool {
	for _, runtime := range runtimes {
		if runtime.Available || len(runtime.Containers) > 0 {
			return true
		}
	}
	return false
}

func runtimeInventoryComplete(runtimes []runtimeinv.Inventory) bool {
	if len(runtimes) == 0 {
		return false
	}
	for _, runtime := range runtimes {
		if !runtime.Available {
			return false
		}
	}
	return true
}

func runningContainerIDs(runtimes []runtimeinv.Inventory) []string {
	var ids []string
	for _, runtime := range runtimes {
		for _, container := range runtime.Containers {
			if container.ID != "" && container.State == "running" {
				ids = append(ids, container.ID)
			}
		}
	}
	return ids
}

func knownContainerIDs(runtimes []runtimeinv.Inventory) []string {
	var ids []string
	for _, runtime := range runtimes {
		for _, container := range runtime.Containers {
			if container.ID != "" {
				ids = append(ids, container.ID)
			}
		}
	}
	return ids
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
