package detect

import (
	"sort"

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
	leaks = append(leaks, DetectStaleNetworkBridges(input)...)
	leaks = append(leaks, DetectStaleRoutes(input)...)
	leaks = append(leaks, DetectStaleCNIAllocations(input)...)
	leaks = append(leaks, DetectStaleNetworkNamespaces(input.Host)...)
	leaks = append(leaks, DetectAbandonedMounts(input)...)
	leaks = append(leaks, DetectDanglingOverlaySnapshots(input)...)
	leaks = append(leaks, DetectStaleCgroups(input)...)
	leaks = append(leaks, DetectOrphanRuntimeProcesses(input)...)
	sortLeaks(leaks)
	return leaks
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
