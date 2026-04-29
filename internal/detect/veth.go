package detect

import (
	"fmt"

	"scrubd/internal/cleanup"
	"scrubd/internal/inspect"
)

func DetectOrphanVeth(input Input) []Leak {
	if runningContainerCount(input.Runtimes) > 0 {
		return nil
	}
	if !runtimeInventoryComplete(input.Runtimes) {
		return nil
	}

	visibleInterfaces := networkInterfaceIndexes(input.Host.NetworkInterfaces)
	var leaks []Leak
	for _, iface := range input.Host.NetworkInterfaces {
		if iface.Kind != "veth" {
			continue
		}
		if iface.PeerIndex != 0 {
			if _, ok := visibleInterfaces[iface.PeerIndex]; ok {
				continue
			}
		}

		leak := NewLeak(
			LeakTypeVethInterface,
			SeverityHigh,
			iface.Name,
			"veth interface found but no running runtime container references are available",
		)
		leak.Evidence = []string{
			fmt.Sprintf("interface index: %d", iface.Index),
			"interface kind: veth",
			vethPeerEvidence(iface),
			"runtime inventories: all selected runtimes available",
			"running containers: 0",
		}
		leak.SafeAction = fmt.Sprintf("ip link delete %s", iface.Name)
		leak.RiskNotes = "delete only after confirming no workload uses this interface"
		leak.CleanupPlan = []cleanup.Step{{
			Description: fmt.Sprintf("delete veth interface %s", iface.Name),
			Command:     []string{"ip", "link", "delete", iface.Name},
			Destructive: true,
		}}
		leaks = append(leaks, leak)
	}
	return leaks
}

func networkInterfaceIndexes(interfaces []inspect.NetworkInterface) map[int]struct{} {
	out := make(map[int]struct{}, len(interfaces))
	for _, iface := range interfaces {
		if iface.Index != 0 {
			out[iface.Index] = struct{}{}
		}
	}
	return out
}

func vethPeerEvidence(iface inspect.NetworkInterface) string {
	if iface.PeerIndex == 0 {
		return "peer interface index: unknown"
	}
	return fmt.Sprintf("peer interface index: %d not visible on host", iface.PeerIndex)
}
