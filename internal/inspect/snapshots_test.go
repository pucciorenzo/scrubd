package inspect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadDockerOverlaySnapshots(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "snap-1", "diff"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "l"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "incomplete"), 0o755); err != nil {
		t.Fatal(err)
	}

	snapshots, warnings := readDockerOverlaySnapshots(root)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %#v, want none", warnings)
	}
	if len(snapshots) != 1 {
		t.Fatalf("len(snapshots) = %d, want 1", len(snapshots))
	}
	if snapshots[0].Runtime != "docker" || snapshots[0].ID != "snap-1" {
		t.Fatalf("unexpected snapshot: %#v", snapshots[0])
	}
}

func TestReadContainerdSnapshots(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "12", "fs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "13"), 0o755); err != nil {
		t.Fatal(err)
	}

	snapshots, warnings := readContainerdSnapshots(root)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %#v, want none", warnings)
	}
	if len(snapshots) != 1 {
		t.Fatalf("len(snapshots) = %d, want 1", len(snapshots))
	}
	if snapshots[0].Runtime != "containerd" || snapshots[0].ID != "12" {
		t.Fatalf("unexpected snapshot: %#v", snapshots[0])
	}
}

func TestSnapshotsIgnoresMissingDirs(t *testing.T) {
	collector := NewCollector(Paths{
		DockerOverlayDir:      filepath.Join(t.TempDir(), "missing-docker"),
		ContainerdSnapshotDir: filepath.Join(t.TempDir(), "missing-containerd"),
	})

	snapshots, warnings := collector.Snapshots()
	if len(snapshots) != 0 || len(warnings) != 0 {
		t.Fatalf("snapshots=%#v warnings=%#v, want empty", snapshots, warnings)
	}
}
