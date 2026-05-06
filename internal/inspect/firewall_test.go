package inspect

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func TestParseIPTablesSave(t *testing.T) {
	input := strings.NewReader(`*nat
:PREROUTING ACCEPT [0:0]
:CNI-HOSTPORT-DNAT - [0:0]
-A PREROUTING -m addrtype --dst-type LOCAL -j CNI-HOSTPORT-DNAT
-A CNI-HOSTPORT-DNAT -i br-deadbeef -j RETURN
-A CNI-HOSTPORT-DNAT ! -o cni-podman0 -j MASQUERADE
-A CNI-HOSTPORT-DNAT --physdev-in=br-wild+ -j ACCEPT
COMMIT
`)

	rules, err := parseIPTablesSave(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 4 {
		t.Fatalf("len(rules) = %d, want 4", len(rules))
	}
	if got := rules[1]; got.Backend != "iptables" || got.Table != "nat" || got.Chain != "CNI-HOSTPORT-DNAT" {
		t.Fatalf("unexpected rule metadata: %#v", got)
	}
	if refs := rules[1].InterfaceRefs; len(refs) != 1 || refs[0] != "br-deadbeef" {
		t.Fatalf("refs = %#v, want br-deadbeef", refs)
	}
	if refs := rules[2].InterfaceRefs; len(refs) != 1 || refs[0] != "cni-podman0" {
		t.Fatalf("refs = %#v, want cni-podman0", refs)
	}
	if refs := rules[3].InterfaceRefs; len(refs) != 1 || refs[0] != "br-wild+" {
		t.Fatalf("refs = %#v, want br-wild+", refs)
	}
}

func TestParseNFTRuleset(t *testing.T) {
	input := strings.NewReader(`table ip nat {
	chain CNI-HOSTPORT-DNAT {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "br-deadbeef" counter packets 0 bytes 0 return # handle 12
		oifname { "cni-podman0", "br-wild+" } masquerade # handle 13
	}
}
`)

	rules, err := parseNFTRuleset(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("len(rules) = %d, want 2", len(rules))
	}
	if got := rules[0]; got.Backend != "nftables" || got.Table != "ip/nat" || got.Chain != "CNI-HOSTPORT-DNAT" {
		t.Fatalf("unexpected rule metadata: %#v", got)
	}
	if refs := rules[0].InterfaceRefs; len(refs) != 1 || refs[0] != "br-deadbeef" {
		t.Fatalf("refs = %#v, want br-deadbeef", refs)
	}
	if refs := rules[1].InterfaceRefs; len(refs) != 2 || refs[0] != "cni-podman0" || refs[1] != "br-wild+" {
		t.Fatalf("refs = %#v, want cni-podman0 and br-wild+", refs)
	}
}

func TestFirewallRulesSkipsMissingCommands(t *testing.T) {
	collector := NewCollector(Paths{
		IPTablesSaveCommand: "iptables-save",
		NFTCommand:          "nft",
	})
	collector.runCommand = func(string, ...string) ([]byte, error) {
		return nil, exec.ErrNotFound
	}

	rules, warnings := collector.FirewallRules()
	if len(rules) != 0 || len(warnings) != 0 {
		t.Fatalf("rules=%#v warnings=%#v, want empty for missing commands", rules, warnings)
	}
}

func TestFirewallRulesWarnsOnCommandFailure(t *testing.T) {
	collector := NewCollector(Paths{IPTablesSaveCommand: "iptables-save"})
	collector.runCommand = func(string, ...string) ([]byte, error) {
		return nil, errors.New("permission denied")
	}

	rules, warnings := collector.FirewallRules()
	if len(rules) != 0 {
		t.Fatalf("rules = %#v, want none", rules)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "permission denied") {
		t.Fatalf("warnings = %#v, want permission denied", warnings)
	}
}
