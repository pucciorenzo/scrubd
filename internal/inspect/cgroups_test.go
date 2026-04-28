package inspect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseCgroupLineV1(t *testing.T) {
	cgroup, ok := parseCgroupLine("3:cpu,cpuacct:/docker/abc123")
	if !ok {
		t.Fatal("parseCgroupLine returned false")
	}

	if cgroup.HierarchyID != "3" || cgroup.Path != "/docker/abc123" {
		t.Fatalf("unexpected cgroup: %#v", cgroup)
	}
	if len(cgroup.Controllers) != 2 || cgroup.Controllers[0] != "cpu" || cgroup.Controllers[1] != "cpuacct" {
		t.Fatalf("unexpected controllers: %#v", cgroup.Controllers)
	}
}

func TestParseCgroupLineV2(t *testing.T) {
	cgroup, ok := parseCgroupLine("0::/system.slice/containerd.service")
	if !ok {
		t.Fatal("parseCgroupLine returned false")
	}

	if cgroup.HierarchyID != "0" || len(cgroup.Controllers) != 0 || cgroup.Path != "/system.slice/containerd.service" {
		t.Fatalf("unexpected cgroup v2 parse: %#v", cgroup)
	}
}

func TestParseCgroupsRejectsInvalidLine(t *testing.T) {
	_, err := parseCgroups(strings.NewReader("bad\n"))
	if err == nil {
		t.Fatal("parseCgroups returned nil error")
	}
}

func TestScanCgroupRootFindsRuntimeCgroups(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{
		"system.slice/docker-leaked.scope",
		"kubepods.slice/pod123",
		"user.slice/user-501.slice",
	} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, dir, "cgroup.procs"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	cgroups, warnings, err := scanCgroupRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %#v, want none", warnings)
	}
	if len(cgroups) != 2 {
		t.Fatalf("cgroups = %#v, want two runtime cgroups", cgroups)
	}
	paths := map[string]bool{}
	for _, cgroup := range cgroups {
		paths[cgroup.Path] = true
	}
	if !paths["/system.slice/docker-leaked.scope"] || !paths["/kubepods.slice/pod123"] {
		t.Fatalf("unexpected cgroups: %#v", cgroups)
	}
	for _, cgroup := range cgroups {
		if !cgroup.ProcessCountKnown || cgroup.ProcessCount != 0 {
			t.Fatalf("cgroup = %#v, want known empty process count", cgroup)
		}
	}
}

func TestScanCgroupRootCountsProcesses(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "system.slice", "docker-leaked.scope")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte("123\n456\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cgroups, warnings, err := scanCgroupRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %#v, want none", warnings)
	}
	if len(cgroups) != 1 || !cgroups[0].ProcessCountKnown || cgroups[0].ProcessCount != 2 {
		t.Fatalf("cgroups = %#v, want process count 2", cgroups)
	}
}

func TestCgroupsScansRootBeforeProcCgroup(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "system.slice", "containerd-leaked.scope"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "system.slice", "containerd-leaked.scope", "cgroup.procs"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	procCgroup := filepath.Join(t.TempDir(), "cgroup")
	if err := os.WriteFile(procCgroup, []byte("0::/user.slice\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cgroups, warnings := NewCollector(Paths{
		CgroupRoot: root,
		Cgroup:     procCgroup,
	}).Cgroups()
	if len(warnings) != 0 {
		t.Fatalf("warnings = %#v, want none", warnings)
	}
	if len(cgroups) != 1 || cgroups[0].Path != "/system.slice/containerd-leaked.scope" {
		t.Fatalf("cgroups = %#v, want root scan result", cgroups)
	}
}
