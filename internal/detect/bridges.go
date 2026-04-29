package detect

import (
	"fmt"
	"strings"

	"scrubd/internal/inspect"
)

func DetectStaleNetworkBridges(input Input) []Leak {
	if !runtimeCorrelationAvailable(input.Runtimes) {
		return nil
	}
	if !runtimeInventoryComplete(input.Runtimes) {
		return nil
	}
	if runningContainerCount(input.Runtimes) > 0 {
		return nil
	}

	var leaks []Leak
	for _, iface := range input.Host.NetworkInterfaces {
		if !staleBridgeCandidate(iface) {
			continue
		}

		leak := NewLeak(
			LeakTypeNetworkBridge,
			SeverityLow,
			iface.Name,
			"runtime-looking bridge has no attached bridge ports and no running runtime containers",
		)
		leak.Evidence = []string{
			fmt.Sprintf("interface index: %d", iface.Index),
			"interface kind: bridge",
			fmt.Sprintf("bridge ports: %d", len(iface.BridgePorts)),
			"runtime inventories: all selected runtimes available",
			"running containers: 0",
		}
		if len(iface.Flags) > 0 {
			leak.Evidence = append(leak.Evidence, "flags: "+strings.Join(iface.Flags, ","))
		}
		leak.SafeAction = "Review runtime network metadata and remove the bridge with runtime or network tooling only if it is no longer configured."
		leak.RiskNotes = "Removing an active bridge can disrupt container, pod, or host networking; scrubd does not generate a direct bridge cleanup command."
		leaks = append(leaks, leak)
	}
	return leaks
}

func staleBridgeCandidate(iface inspect.NetworkInterface) bool {
	return iface.Kind == "bridge" &&
		iface.BridgePortsKnown &&
		runtimeBridgeName(iface.Name) &&
		len(iface.BridgePorts) == 0
}

func runtimeBridgeName(name string) bool {
	switch {
	case name == "docker0", name == "cni0", name == "podman0":
		return false
	case strings.HasPrefix(name, "br-"):
		return true
	case strings.HasPrefix(name, "cni"):
		return true
	case strings.HasPrefix(name, "podman"):
		return true
	default:
		return false
	}
}
