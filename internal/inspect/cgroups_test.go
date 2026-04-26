package inspect

import (
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
