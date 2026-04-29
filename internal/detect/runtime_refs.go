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
	value = strings.ToLower(value)
	for _, id := range ids {
		id = strings.ToLower(strings.TrimSpace(id))
		if id != "" && containsContainerIDReference(value, id) {
			return true
		}
	}
	return false
}

func containsContainerIDReference(value, id string) bool {
	offset := 0
	for {
		idx := strings.Index(value[offset:], id)
		if idx < 0 {
			return false
		}
		idx += offset
		beforeOK := idx == 0 || !containerIDChar(value[idx-1])
		after := idx + len(id)
		afterOK := after == len(value) || !containerIDChar(value[after])
		if beforeOK && afterOK {
			return true
		}
		offset = idx + 1
	}
}

func containerIDChar(value byte) bool {
	return (value >= '0' && value <= '9') ||
		(value >= 'a' && value <= 'z') ||
		(value >= 'A' && value <= 'Z')
}
