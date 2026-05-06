package inspect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadRuntimeStateRoot(t *testing.T) {
	root := t.TempDir()
	taskID := "abcdef1234567890"
	if err := os.MkdirAll(filepath.Join(root, "k8s.io", taskID), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "k8s.io", "not-a-container"), 0o755); err != nil {
		t.Fatal(err)
	}

	states, err := readRuntimeStateRoot(RuntimeStateRoot{
		Runtime:  "containerd",
		Kind:     "containerd_task",
		Path:     root,
		MaxDepth: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 {
		t.Fatalf("len(states) = %d, want 1: %#v", len(states), states)
	}
	if states[0].Runtime != "containerd" || states[0].Kind != "containerd_task" || states[0].ID != taskID {
		t.Fatalf("state = %#v", states[0])
	}
}

func TestReadRuntimeStateRootMissing(t *testing.T) {
	states, err := readRuntimeStateRoot(RuntimeStateRoot{Path: filepath.Join(t.TempDir(), "missing")})
	if err != nil {
		t.Fatal(err)
	}
	if states != nil {
		t.Fatalf("states = %#v, want nil", states)
	}
}

func TestRuntimeStateID(t *testing.T) {
	for _, value := range []string{
		"abcdef123456",
		"abcdef12-3456-7890-abcd-ef1234567890",
	} {
		if !runtimeStateID(value) {
			t.Fatalf("runtimeStateID(%q) = false", value)
		}
	}
	for _, value := range []string{"short", "not-a-container", "zzzzzzzzzzzz"} {
		if runtimeStateID(value) {
			t.Fatalf("runtimeStateID(%q) = true", value)
		}
	}
}
