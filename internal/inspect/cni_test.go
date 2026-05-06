package inspect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadCNIAllocations(t *testing.T) {
	root := t.TempDir()
	networkDir := filepath.Join(root, "mynet")
	if err := os.MkdirAll(networkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(networkDir, "10.88.0.2"), []byte("abcdef1234567890\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(networkDir, "last_reserved_ip"), []byte("10.88.0.2"), 0o644); err != nil {
		t.Fatal(err)
	}

	allocations, err := readCNIAllocations(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(allocations) != 1 {
		t.Fatalf("len(allocations) = %d, want 1", len(allocations))
	}
	got := allocations[0]
	if got.Network != "mynet" || got.IP != "10.88.0.2" || got.ContainerID != "abcdef1234567890" || got.Source != "cni_ipam" {
		t.Fatalf("allocation = %#v", got)
	}
}

func TestReadCNIAllocationsMissingRoot(t *testing.T) {
	allocations, err := readCNIAllocations(filepath.Join(t.TempDir(), "missing"))
	if err != nil {
		t.Fatal(err)
	}
	if allocations != nil {
		t.Fatalf("allocations = %#v, want nil", allocations)
	}
}

func TestReadCNIStateFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "stale"), []byte(`{
		"kind": "cniCacheV1",
		"containerId": "abcdef1234567890",
		"networkName": "mynet"
	}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "metadata"), []byte(`{"kind":"metadata"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	files, err := readCNIStateFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("len(files) = %d, want 1", len(files))
	}
	got := files[0]
	if got.Kind != "cniCacheV1" || got.Network != "mynet" || got.ContainerID != "abcdef1234567890" || got.Source != "cni_result_cache" {
		t.Fatalf("unexpected state file: %#v", got)
	}
}

func TestReadCNIStateFilesMissingRoot(t *testing.T) {
	files, err := readCNIStateFiles(filepath.Join(t.TempDir(), "missing"))
	if err != nil {
		t.Fatal(err)
	}
	if files != nil {
		t.Fatalf("files = %#v, want nil", files)
	}
}

func TestParseCNIStateFileSkipsUnstructuredText(t *testing.T) {
	state := parseCNIStateFile("/var/lib/cni/results/stale", []byte("container abcdef1234567890"))
	if state.ContainerID != "" {
		t.Fatalf("container id = %q, want empty for unstructured text", state.ContainerID)
	}
}
