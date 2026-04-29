package detect

import (
	"fmt"

	"scrubd/internal/cleanup"
	"scrubd/internal/inspect"
)

func DetectStaleNetworkNamespaces(host inspect.Inventory) []Leak {
	processInodes := map[string]struct{}{}
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

func nsName(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
}
