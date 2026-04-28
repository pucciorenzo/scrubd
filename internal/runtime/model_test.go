package runtime

import (
	"path/filepath"
	"testing"
)

func TestValidName(t *testing.T) {
	for _, name := range []Name{NameAuto, NameDocker, NameContainerd} {
		if !ValidName(name) {
			t.Fatalf("ValidName(%q) = false", name)
		}
	}
	if ValidName("podman") {
		t.Fatal("ValidName accepted podman")
	}
}

func TestInventories(t *testing.T) {
	collector := NewCollector(Paths{})

	if got := collector.Inventories(NameDocker); len(got) != 1 || got[0].Runtime != NameDocker {
		t.Fatalf("docker inventories = %#v", got)
	}
	if got := collector.Inventories(NameContainerd); len(got) != 1 || got[0].Runtime != NameContainerd {
		t.Fatalf("containerd inventories = %#v", got)
	}
	if got := collector.Inventories(NameAuto); len(got) != 2 {
		t.Fatalf("auto inventories len = %d, want 2", len(got))
	}
}

func TestSocketCandidatesDeduplicatesAndSkipsEmpty(t *testing.T) {
	got := socketCandidates("/run/docker.sock", []string{"", "/run/docker.sock", "/run/user/501/docker.sock"})
	want := []string{"/run/docker.sock", "/run/user/501/docker.sock"}
	if len(got) != len(want) {
		t.Fatalf("candidates = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidates = %#v, want %#v", got, want)
		}
	}
}

func TestRootlessSocketPaths(t *testing.T) {
	runtimeDir := filepath.Join("run", "user", "501")
	docker := rootlessDockerSockets(runtimeDir, 501)
	if len(docker) != 2 || docker[0] != filepath.Join(runtimeDir, "docker.sock") || docker[1] != "/run/user/501/docker.sock" {
		t.Fatalf("docker sockets = %#v", docker)
	}

	containerd := rootlessContainerdSockets(runtimeDir, 501)
	if len(containerd) != 2 || containerd[0] != filepath.Join(runtimeDir, "containerd", "containerd.sock") || containerd[1] != "/run/user/501/containerd/containerd.sock" {
		t.Fatalf("containerd sockets = %#v", containerd)
	}
}
