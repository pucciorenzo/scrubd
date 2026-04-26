package inspect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNamespaceInode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "net")
	if err := os.Symlink("net:[4026531993]", path); err != nil {
		t.Fatal(err)
	}

	if inode := namespaceInode(path); inode != "4026531993" {
		t.Fatalf("namespaceInode = %q", inode)
	}
}

func TestReadNamedNetworkNamespacesIgnoresDirectories(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink("net:[1]", filepath.Join(dir, "cni-a")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}

	namespaces, err := readNamedNetworkNamespaces(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(namespaces) != 1 {
		t.Fatalf("len(namespaces) = %d, want 1", len(namespaces))
	}
	if namespaces[0].Inode != "1" || namespaces[0].Source != "netns" {
		t.Fatalf("unexpected namespace: %#v", namespaces[0])
	}
}
