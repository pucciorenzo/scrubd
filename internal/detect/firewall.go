package detect

import (
	"fmt"
	"strings"

	"scrubd/internal/inspect"
)

func DetectStaleFirewallRules(input Input) []Leak {
	if !runtimeCorrelationAvailable(input.Runtimes) {
		return nil
	}

	interfaces := networkInterfaceNames(input.Host.NetworkInterfaces)
	var leaks []Leak
	for _, rule := range input.Host.FirewallRules {
		for _, ref := range rule.InterfaceRefs {
			if !staleFirewallInterfaceRef(ref, interfaces) {
				continue
			}

			leak := NewLeak(
				LeakTypeFirewallRule,
				SeverityLow,
				firewallRuleResource(rule, ref),
				"firewall rule references a missing runtime-looking network interface",
			)
			leak.Evidence = []string{
				"backend: " + rule.Backend,
				"table: " + rule.Table,
				"chain: " + rule.Chain,
				"interface ref: " + ref,
				"rule: " + rule.Raw,
				"source: " + rule.Source,
				fmt.Sprintf("interface present: %t", false),
			}
			leak.SafeAction = "Review runtime or CNI network metadata and remove the stale firewall rule with firewall tooling only if it is no longer configured."
			leak.RiskNotes = "Removing active firewall rules can disrupt container, pod, or host networking; scrubd does not generate a direct firewall cleanup command."
			leaks = append(leaks, leak)
		}
	}
	return leaks
}

func staleFirewallInterfaceRef(ref string, interfaces map[string]struct{}) bool {
	if ref == "" || !runtimeFirewallInterfaceRef(ref) {
		return false
	}
	return !firewallInterfaceRefPresent(ref, interfaces)
}

func runtimeFirewallInterfaceRef(ref string) bool {
	ref = strings.TrimSuffix(ref, "+")
	return runtimeNetworkInterfaceName(ref)
}

func firewallInterfaceRefPresent(ref string, interfaces map[string]struct{}) bool {
	if strings.HasSuffix(ref, "+") {
		prefix := strings.TrimSuffix(ref, "+")
		for name := range interfaces {
			if strings.HasPrefix(name, prefix) {
				return true
			}
		}
		return false
	}
	_, ok := interfaces[ref]
	return ok
}

func firewallRuleResource(rule inspect.FirewallRule, ref string) string {
	parts := []string{rule.Backend}
	if rule.Table != "" {
		parts = append(parts, rule.Table)
	}
	if rule.Chain != "" {
		parts = append(parts, rule.Chain)
	}
	parts = append(parts, ref)
	return strings.Join(parts, " ")
}
