package inspect

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestInterfacePeerIndex(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "veth0"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "veth0", "iflink"), []byte("42\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	collector := NewCollector(Paths{NetClassDir: root})
	got := collector.interfacePeerIndex(net.Interface{Name: "veth0", Index: 7})
	if got != 42 {
		t.Fatalf("peer index = %d, want 42", got)
	}
}

func TestInterfacePeerIndexSkipsSelfLink(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "eth0"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "eth0", "iflink"), []byte("7\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	collector := NewCollector(Paths{NetClassDir: root})
	got := collector.interfacePeerIndex(net.Interface{Name: "eth0", Index: 7})
	if got != 0 {
		t.Fatalf("peer index = %d, want 0 for self link", got)
	}
}

func TestInterfaceKindUsesBridgeDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "custom0", "bridge"), 0o755); err != nil {
		t.Fatal(err)
	}

	collector := NewCollector(Paths{NetClassDir: root})
	got := collector.interfaceKind("custom0")
	if got != "bridge" {
		t.Fatalf("kind = %q, want bridge", got)
	}
}

func TestInterfaceBridgePorts(t *testing.T) {
	root := t.TempDir()
	brif := filepath.Join(root, "br-test", "brif")
	if err := os.MkdirAll(brif, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"vethb", "vetha"} {
		if err := os.WriteFile(filepath.Join(brif, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	collector := NewCollector(Paths{NetClassDir: root})
	got, ok := collector.interfaceBridgePorts("br-test")
	if !ok {
		t.Fatal("bridge ports not known")
	}
	want := []string{"vetha", "vethb"}
	if len(got) != len(want) {
		t.Fatalf("ports = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ports = %#v, want %#v", got, want)
		}
	}
}

func TestInterfaceBridgePortsUnknownWhenMissing(t *testing.T) {
	collector := NewCollector(Paths{NetClassDir: t.TempDir()})
	got, ok := collector.interfaceBridgePorts("not-a-bridge")
	if ok || got != nil {
		t.Fatalf("ports = %#v, known = %v, want unknown missing bridge ports", got, ok)
	}
}
