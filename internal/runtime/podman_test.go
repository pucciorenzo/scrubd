package runtime

import (
	"fmt"
	"net/http"
	"testing"
)

func TestPodmanInventory(t *testing.T) {
	socketPath := tempSocketPath(t, "podman.sock")
	server := newUnixHTTPServer(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/containers/json":
			if r.URL.Query().Get("all") != "true" {
				t.Fatalf("all query = %q", r.URL.Query().Get("all"))
			}
			fmt.Fprint(w, `[{
				"Id":"abc123",
				"Names":["web"],
				"Image":"quay.io/libpod/alpine:latest",
				"State":"running",
				"Status":"Up 5 seconds",
				"Networks":{"podman":{}}
			}]`)
		case "/containers/abc123/json":
			fmt.Fprint(w, `{"State":{"Pid":4321}}`)
		default:
			t.Fatalf("path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	inv := NewCollector(Paths{PodmanSocket: socketPath}).Podman()
	if !inv.Available {
		t.Fatalf("Podman inventory unavailable: %#v", inv.Warnings)
	}
	if len(inv.Containers) != 1 {
		t.Fatalf("len(containers) = %d, want 1", len(inv.Containers))
	}

	container := inv.Containers[0]
	if container.ID != "abc123" || container.Names[0] != "web" || container.NetworkMode != "podman" || container.PID != 4321 {
		t.Fatalf("unexpected container: %#v", container)
	}
}

func TestPodmanInventoryIncludesStoppedContainers(t *testing.T) {
	socketPath := tempSocketPath(t, "podman.sock")
	server := newUnixHTTPServer(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/containers/json":
			fmt.Fprint(w, `[{"Id":"abc123","Names":["web"],"State":"running"},{"Id":"def456","Names":["job"],"State":"exited","Status":"Exited (0) 10 seconds ago"}]`)
		case "/containers/abc123/json":
			fmt.Fprint(w, `{"State":{"Pid":4321}}`)
		case "/containers/def456/json":
			fmt.Fprint(w, `{"State":{"Pid":0}}`)
		default:
			t.Fatalf("path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	inv := NewCollector(Paths{PodmanSocket: socketPath}).Podman()
	if len(inv.Containers) != 2 {
		t.Fatalf("len(containers) = %d, want 2", len(inv.Containers))
	}
	if inv.Containers[1].ID != "def456" || inv.Containers[1].State != "exited" {
		t.Fatalf("unexpected stopped container: %#v", inv.Containers[1])
	}
}

func TestPodmanInventoryFallsBackToRootlessSocket(t *testing.T) {
	socketPath := tempSocketPath(t, "podman.sock")
	server := newUnixHTTPServer(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/containers/json":
			fmt.Fprint(w, `[{"Id":"abc123","Names":["web"],"State":"running"}]`)
		case "/containers/abc123/json":
			fmt.Fprint(w, `{"State":{"Pid":4321}}`)
		default:
			t.Fatalf("path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	inv := NewCollector(Paths{
		PodmanSocket:  tempSocketPath(t, "missing.sock"),
		PodmanSockets: []string{socketPath},
	}).Podman()
	if !inv.Available {
		t.Fatalf("Podman inventory unavailable: %#v", inv.Warnings)
	}
	if len(inv.Warnings) != 0 {
		t.Fatalf("warnings = %#v, want none after fallback succeeds", inv.Warnings)
	}
	if len(inv.Containers) != 1 || inv.Containers[0].ID != "abc123" {
		t.Fatalf("containers = %#v, want fallback inventory", inv.Containers)
	}
}

func TestPodmanInventoryWarnsOnMalformedJSON(t *testing.T) {
	socketPath := tempSocketPath(t, "podman.sock")
	server := newUnixHTTPServer(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/containers/json":
			fmt.Fprint(w, `[`)
		default:
			t.Fatalf("path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	inv := NewCollector(Paths{PodmanSocket: socketPath}).Podman()
	if inv.Available {
		t.Fatal("Podman inventory available for malformed JSON")
	}
	if len(inv.Warnings) != 1 || !contains(inv.Warnings[0], "podman API unavailable: decode") {
		t.Fatalf("warnings = %#v, want decode warning", inv.Warnings)
	}
}

func TestPodmanInventoryMissingSocket(t *testing.T) {
	inv := NewCollector(Paths{PodmanSocket: tempSocketPath(t, "missing.sock")}).Podman()
	if inv.Available {
		t.Fatal("Podman inventory available for missing socket")
	}
	if len(inv.Warnings) != 1 {
		t.Fatalf("warnings = %#v", inv.Warnings)
	}
	if !contains(inv.Warnings[0], "podman socket missing: checked") {
		t.Fatalf("warning = %q, want checked socket warning", inv.Warnings[0])
	}
}
