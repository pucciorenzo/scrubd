package inspect

import (
	"strings"
	"testing"
)

func TestParseMountInfoLine(t *testing.T) {
	line := `36 25 0:32 / /run/docker/netns rw,nosuid,nodev shared:18 - tmpfs tmpfs rw,size=65536k`

	mount, ok := parseMountInfoLine(line)
	if !ok {
		t.Fatal("parseMountInfoLine returned false")
	}

	if mount.ID != "36" || mount.ParentID != "25" || mount.MountPoint != "/run/docker/netns" {
		t.Fatalf("unexpected mount identity: %#v", mount)
	}
	if mount.FSType != "tmpfs" || mount.Source != "tmpfs" {
		t.Fatalf("unexpected mount source: %#v", mount)
	}
	if len(mount.Options) != 3 || mount.Options[0] != "rw" {
		t.Fatalf("unexpected mount options: %#v", mount.Options)
	}
}

func TestParseMountInfoUnescapesMountPoint(t *testing.T) {
	line := `42 36 0:40 / /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs\040copy rw,relatime - overlay overlay rw,lowerdir=/lower`

	mount, ok := parseMountInfoLine(line)
	if !ok {
		t.Fatal("parseMountInfoLine returned false")
	}
	if mount.MountPoint != "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs copy" {
		t.Fatalf("MountPoint = %q", mount.MountPoint)
	}
}

func TestParseMountInfoRejectsInvalidLine(t *testing.T) {
	_, err := parseMountInfo(strings.NewReader("invalid\n"))
	if err == nil {
		t.Fatal("parseMountInfo returned nil error")
	}
}
