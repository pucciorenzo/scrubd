package inspect

import (
	"strings"
	"testing"
)

func TestParseProcNetRoute(t *testing.T) {
	input := strings.NewReader(`Iface	Destination	Gateway	Flags	RefCnt	Use	Metric	Mask	MTU	Window	IRTT
eth0	00000000	0102A8C0	0003	0	0	100	00000000	0	0	0
br-test	0002A8C0	00000000	0001	0	0	0	00FFFFFF	0	0	0
`)

	routes, err := parseProcNetRoute(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 {
		t.Fatalf("len(routes) = %d, want 2", len(routes))
	}
	if routes[0].Interface != "eth0" || routes[0].Destination != "0.0.0.0" || routes[0].Gateway != "192.168.2.1" {
		t.Fatalf("unexpected default route: %#v", routes[0])
	}
	if routes[1].Interface != "br-test" || routes[1].Destination != "192.168.2.0" || routes[1].Mask != "255.255.255.0" {
		t.Fatalf("unexpected bridge route: %#v", routes[1])
	}
}

func TestParseProcNetRouteRejectsInvalidLine(t *testing.T) {
	input := strings.NewReader(`Iface	Destination	Gateway	Flags	RefCnt	Use	Metric	Mask
bad	00000000
`)

	if _, err := parseProcNetRoute(input); err == nil {
		t.Fatal("parseProcNetRoute returned nil error")
	}
}

func TestParseRouteIPv4(t *testing.T) {
	got, err := parseRouteIPv4("0102A8C0")
	if err != nil {
		t.Fatal(err)
	}
	if got != "192.168.2.1" {
		t.Fatalf("ip = %q, want 192.168.2.1", got)
	}
}
