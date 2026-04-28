package inspect

import (
	"strings"
	"testing"
)

func TestInventorySkipsUnsupportedOS(t *testing.T) {
	inv := NewCollector(Paths{}).inventory("darwin")

	if len(inv.Warnings) != 1 {
		t.Fatalf("warnings = %#v, want one unsupported OS warning", inv.Warnings)
	}
	if !strings.Contains(inv.Warnings[0], "unsupported on darwin") {
		t.Fatalf("warning = %q, want unsupported OS detail", inv.Warnings[0])
	}
	if len(inv.NetworkInterfaces) != 0 || len(inv.Mounts) != 0 || len(inv.Processes) != 0 {
		t.Fatalf("inventory = %#v, want empty host resources", inv)
	}
}
