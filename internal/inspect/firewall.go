package inspect

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"
)

func (c Collector) FirewallRules() ([]FirewallRule, []string) {
	var rules []FirewallRule
	var warnings []string

	if c.paths.IPTablesSaveCommand != "" {
		parsed, warning := c.firewallRulesFromCommand(c.paths.IPTablesSaveCommand, nil, parseIPTablesSave)
		rules = append(rules, parsed...)
		if warning != "" {
			warnings = append(warnings, warning)
		}
	}
	if c.paths.NFTCommand != "" {
		parsed, warning := c.firewallRulesFromCommand(c.paths.NFTCommand, []string{"-a", "list", "ruleset"}, parseNFTRuleset)
		rules = append(rules, parsed...)
		if warning != "" {
			warnings = append(warnings, warning)
		}
	}

	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Backend != rules[j].Backend {
			return rules[i].Backend < rules[j].Backend
		}
		if rules[i].Table != rules[j].Table {
			return rules[i].Table < rules[j].Table
		}
		if rules[i].Chain != rules[j].Chain {
			return rules[i].Chain < rules[j].Chain
		}
		return rules[i].Raw < rules[j].Raw
	})
	return rules, warnings
}

func (c Collector) firewallRulesFromCommand(command string, args []string, parser func(io.Reader) ([]FirewallRule, error)) ([]FirewallRule, string) {
	output, err := c.runCommand(command, args...)
	if errors.Is(err, exec.ErrNotFound) {
		return nil, ""
	}
	if err != nil {
		return nil, fmt.Sprintf("firewall rules: %s: %v", command, err)
	}

	rules, err := parser(strings.NewReader(string(output)))
	if err != nil {
		return nil, fmt.Sprintf("firewall rules: %s: %v", command, err)
	}
	return rules, ""
}

func parseIPTablesSave(input io.Reader) ([]FirewallRule, error) {
	scanner := bufio.NewScanner(input)
	var table string
	var rules []FirewallRule

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "*") {
			table = strings.TrimPrefix(line, "*")
			continue
		}
		if line == "COMMIT" {
			table = ""
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		if !strings.HasPrefix(line, "-A ") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("invalid iptables-save rule %q", line)
		}
		rules = append(rules, FirewallRule{
			Backend:       "iptables",
			Table:         table,
			Chain:         fields[1],
			Raw:           line,
			InterfaceRefs: iptablesInterfaceRefs(fields[2:]),
			Source:        "iptables-save",
		})
	}
	return rules, scanner.Err()
}

func iptablesInterfaceRefs(fields []string) []string {
	var refs []string
	for i := 0; i < len(fields); i++ {
		field := fields[i]
		if field == "!" {
			continue
		}
		if ref, ok := strings.CutPrefix(field, "--in-interface="); ok {
			refs = appendFirewallInterfaceRef(refs, ref)
			continue
		}
		if ref, ok := strings.CutPrefix(field, "--out-interface="); ok {
			refs = appendFirewallInterfaceRef(refs, ref)
			continue
		}
		if ref, ok := strings.CutPrefix(field, "--physdev-in="); ok {
			refs = appendFirewallInterfaceRef(refs, ref)
			continue
		}
		if ref, ok := strings.CutPrefix(field, "--physdev-out="); ok {
			refs = appendFirewallInterfaceRef(refs, ref)
			continue
		}
		if !iptablesInterfaceFlag(field) {
			continue
		}

		next := i + 1
		for next < len(fields) && fields[next] == "!" {
			next++
		}
		if next >= len(fields) {
			continue
		}
		refs = appendFirewallInterfaceRef(refs, fields[next])
		i = next
	}
	return refs
}

func iptablesInterfaceFlag(field string) bool {
	switch field {
	case "-i", "--in-interface", "-o", "--out-interface", "--physdev-in", "--physdev-out":
		return true
	default:
		return false
	}
}

func parseNFTRuleset(input io.Reader) ([]FirewallRule, error) {
	scanner := bufio.NewScanner(input)
	var table string
	var chain string
	var rules []FirewallRule

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "table" {
			table = fields[1] + "/" + fields[2]
			continue
		}
		if len(fields) >= 2 && fields[0] == "chain" {
			chain = fields[1]
			continue
		}
		if line == "}" {
			if chain != "" {
				chain = ""
			} else {
				table = ""
			}
			continue
		}
		if chain == "" || strings.HasPrefix(line, "type ") || strings.HasPrefix(line, "policy ") {
			continue
		}

		refs := nftInterfaceRefs(line)
		if len(refs) == 0 {
			continue
		}
		rules = append(rules, FirewallRule{
			Backend:       "nftables",
			Table:         table,
			Chain:         chain,
			Raw:           line,
			InterfaceRefs: refs,
			Source:        "nft list ruleset",
		})
	}
	return rules, scanner.Err()
}

func nftInterfaceRefs(line string) []string {
	replacer := strings.NewReplacer("{", " { ", "}", " } ", ",", " ")
	fields := strings.Fields(replacer.Replace(line))

	var refs []string
	for i := 0; i < len(fields); i++ {
		if fields[i] != "iifname" && fields[i] != "oifname" {
			continue
		}
		next := i + 1
		if next < len(fields) && fields[next] == "!=" {
			next++
		}
		if next >= len(fields) {
			continue
		}
		if fields[next] != "{" {
			refs = appendFirewallInterfaceRef(refs, fields[next])
			i = next
			continue
		}

		for next++; next < len(fields) && fields[next] != "}"; next++ {
			refs = appendFirewallInterfaceRef(refs, fields[next])
		}
		i = next
	}
	return refs
}

func appendFirewallInterfaceRef(refs []string, value string) []string {
	value = normalizeFirewallInterfaceRef(value)
	if value == "" {
		return refs
	}
	for _, ref := range refs {
		if ref == value {
			return refs
		}
	}
	return append(refs, value)
}

func normalizeFirewallInterfaceRef(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'`)
	value = strings.TrimSuffix(value, ",")
	value = strings.Trim(value, `"'`)
	switch value {
	case "", "!", "{", "}", "vmap", "map":
		return ""
	default:
		return value
	}
}
