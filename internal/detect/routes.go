package detect

import (
	"fmt"

	"scrubd/internal/inspect"
)

func DetectStaleRoutes(input Input) []Leak {
	if !runtimeCorrelationAvailable(input.Runtimes) {
		return nil
	}

	interfaces := networkInterfaceNames(input.Host.NetworkInterfaces)
	var leaks []Leak
	for _, route := range input.Host.Routes {
		if !staleRouteCandidate(route, interfaces) {
			continue
		}

		resource := route.Interface + " " + route.Destination + "/" + route.Mask
		leak := NewLeak(
			LeakTypeRoute,
			SeverityLow,
			resource,
			"route references a missing runtime-looking network interface",
		)
		leak.Evidence = []string{
			"interface: " + route.Interface,
			"destination: " + route.Destination,
			"mask: " + route.Mask,
			"gateway: " + route.Gateway,
			"source: " + route.Source,
			fmt.Sprintf("interface present: %t", false),
		}
		leak.SafeAction = "Review runtime or CNI network metadata and remove the stale route with network tooling only if the route is no longer configured."
		leak.RiskNotes = "Removing an active route can disrupt container, pod, or host networking; scrubd does not generate a direct route cleanup command."
		leaks = append(leaks, leak)
	}
	return leaks
}

func networkInterfaceNames(interfaces []inspect.NetworkInterface) map[string]struct{} {
	names := make(map[string]struct{}, len(interfaces))
	for _, iface := range interfaces {
		if iface.Name == "" {
			continue
		}
		names[iface.Name] = struct{}{}
	}
	return names
}

func staleRouteCandidate(route inspect.Route, interfaces map[string]struct{}) bool {
	if route.Interface == "" || !runtimeNetworkInterfaceName(route.Interface) {
		return false
	}
	_, ok := interfaces[route.Interface]
	return !ok
}

func runtimeNetworkInterfaceName(name string) bool {
	return runtimeBridgeName(name)
}
