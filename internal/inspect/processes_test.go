package inspect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadProcesses(t *testing.T) {
	procDir := t.TempDir()
	processDir := filepath.Join(procDir, "123")
	if err := os.Mkdir(processDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(procDir, "not-a-pid"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(processDir, "comm"), []byte("containerd-shim\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(processDir, "cmdline"), []byte("containerd-shim\x00-namespace\x00k8s.io\x00"), 0o644); err != nil {
		t.Fatal(err)
	}

	processes, err := readProcesses(procDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(processes) != 1 {
		t.Fatalf("len(processes) = %d, want 1", len(processes))
	}
	if processes[0].PID != 123 || processes[0].Command != "containerd-shim" {
		t.Fatalf("unexpected process: %#v", processes[0])
	}
	if len(processes[0].Args) != 3 || processes[0].Args[0] != "containerd-shim" {
		t.Fatalf("unexpected args: %#v", processes[0].Args)
	}
}
