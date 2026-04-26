package runtime

import "testing"

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
