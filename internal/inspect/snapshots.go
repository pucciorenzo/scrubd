package inspect

import (
	"fmt"
	"os"
	"path/filepath"
)

func (c Collector) Snapshots() ([]Snapshot, []string) {
	var snapshots []Snapshot
	var warnings []string

	docker, dockerWarnings := readDockerOverlaySnapshots(c.paths.DockerOverlayDir)
	snapshots = append(snapshots, docker...)
	warnings = append(warnings, dockerWarnings...)

	containerd, containerdWarnings := readContainerdSnapshots(c.paths.ContainerdSnapshotDir)
	snapshots = append(snapshots, containerd...)
	warnings = append(warnings, containerdWarnings...)

	return snapshots, warnings
}

func readDockerOverlaySnapshots(root string) ([]Snapshot, []string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, []string{fmt.Sprintf("docker overlay snapshots: %v", err)}
	}

	var snapshots []Snapshot
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "l" {
			continue
		}
		path := filepath.Join(root, entry.Name())
		if _, err := os.Stat(filepath.Join(path, "diff")); err != nil {
			continue
		}
		snapshots = append(snapshots, Snapshot{
			Runtime: "docker",
			ID:      entry.Name(),
			Path:    path,
		})
	}
	return snapshots, nil
}

func readContainerdSnapshots(root string) ([]Snapshot, []string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, []string{fmt.Sprintf("containerd overlay snapshots: %v", err)}
	}

	var snapshots []Snapshot
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(root, entry.Name())
		if _, err := os.Stat(filepath.Join(path, "fs")); err != nil {
			continue
		}
		snapshots = append(snapshots, Snapshot{
			Runtime: "containerd",
			ID:      entry.Name(),
			Path:    path,
		})
	}
	return snapshots, nil
}
