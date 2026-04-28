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
