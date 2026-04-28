package runtime

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
)

func TestDockerInventory(t *testing.T) {
	socketPath := tempSocketPath(t, "docker.sock")
	server := newUnixHTTPServer(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/containers/json":
			if r.URL.Query().Get("all") != "true" {
				t.Fatalf("all query = %q", r.URL.Query().Get("all"))
			}
			fmt.Fprint(w, `[{
				"Id":"abc123",
				"Names":["/web"],
				"Image":"nginx:latest",
				"State":"running",
				"Status":"Up 5 seconds",
				"NetworkSettings":{"Networks":{"bridge":{"NetworkID":"net1"}}}
			}]`)
		case "/containers/abc123/json":
			fmt.Fprint(w, `{"State":{"Pid":4321}}`)
		default:
			t.Fatalf("path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	inv := NewCollector(Paths{DockerSocket: socketPath}).Docker()
	if !inv.Available {
		t.Fatalf("Docker inventory unavailable: %#v", inv.Warnings)
	}
	if len(inv.Containers) != 1 {
		t.Fatalf("len(containers) = %d, want 1", len(inv.Containers))
	}

	container := inv.Containers[0]
	if container.ID != "abc123" || container.Names[0] != "web" || container.NetworkMode != "bridge" || container.PID != 4321 {
		t.Fatalf("unexpected container: %#v", container)
	}
}

func TestDockerInventoryIncludesStoppedContainers(t *testing.T) {
	socketPath := tempSocketPath(t, "docker.sock")
	server := newUnixHTTPServer(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/containers/json":
			fmt.Fprint(w, `[{"Id":"abc123","Names":["/web"],"State":"running"},{"Id":"def456","Names":["/job"],"State":"exited","Status":"Exited (0) 10 seconds ago"}]`)
		case "/containers/abc123/json":
			fmt.Fprint(w, `{"State":{"Pid":4321}}`)
		case "/containers/def456/json":
			fmt.Fprint(w, `{"State":{"Pid":0}}`)
		default:
			t.Fatalf("path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	inv := NewCollector(Paths{DockerSocket: socketPath}).Docker()
	if len(inv.Containers) != 2 {
		t.Fatalf("len(containers) = %d, want 2", len(inv.Containers))
	}
	if inv.Containers[1].ID != "def456" || inv.Containers[1].State != "exited" {
		t.Fatalf("unexpected stopped container: %#v", inv.Containers[1])
	}
}

func TestDockerInventoryFallsBackToRootlessSocket(t *testing.T) {
	socketPath := tempSocketPath(t, "docker.sock")
	server := newUnixHTTPServer(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/containers/json":
			fmt.Fprint(w, `[{"Id":"abc123","Names":["/web"],"State":"running"}]`)
		case "/containers/abc123/json":
			fmt.Fprint(w, `{"State":{"Pid":4321}}`)
		default:
			t.Fatalf("path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	inv := NewCollector(Paths{
		DockerSocket:  tempSocketPath(t, "missing.sock"),
		DockerSockets: []string{socketPath},
	}).Docker()
	if !inv.Available {
		t.Fatalf("Docker inventory unavailable: %#v", inv.Warnings)
	}
	if len(inv.Warnings) != 0 {
		t.Fatalf("warnings = %#v, want none after fallback succeeds", inv.Warnings)
	}
	if len(inv.Containers) != 1 || inv.Containers[0].ID != "abc123" {
		t.Fatalf("containers = %#v, want fallback inventory", inv.Containers)
	}
}

func TestDockerInventoryKeepsContainerWhenInspectFails(t *testing.T) {
	socketPath := tempSocketPath(t, "docker.sock")
	server := newUnixHTTPServer(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/containers/json":
			fmt.Fprint(w, `[{"Id":"abc123","Names":["/web"],"State":"running"}]`)
		case "/containers/abc123/json":
			http.Error(w, "missing", http.StatusNotFound)
		default:
			t.Fatalf("path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	inv := NewCollector(Paths{DockerSocket: socketPath}).Docker()
	if !inv.Available {
		t.Fatalf("Docker inventory unavailable: %#v", inv.Warnings)
	}
	if len(inv.Containers) != 1 {
		t.Fatalf("len(containers) = %d, want 1", len(inv.Containers))
	}
	if len(inv.Warnings) != 1 {
		t.Fatalf("warnings = %#v, want one inspect warning", inv.Warnings)
	}
	if inv.Containers[0].PID != 0 {
		t.Fatalf("pid = %d, want 0", inv.Containers[0].PID)
	}
}

func TestDockerInventoryWarnsOnMalformedJSON(t *testing.T) {
	socketPath := tempSocketPath(t, "docker.sock")
	server := newUnixHTTPServer(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/containers/json":
			fmt.Fprint(w, `[`)
		default:
			t.Fatalf("path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	inv := NewCollector(Paths{DockerSocket: socketPath}).Docker()
	if inv.Available {
		t.Fatal("Docker inventory available for malformed JSON")
	}
	if len(inv.Warnings) != 1 || !contains(inv.Warnings[0], "docker API unavailable: decode") {
		t.Fatalf("warnings = %#v, want decode warning", inv.Warnings)
	}
}

func TestDockerInventoryMissingSocket(t *testing.T) {
	inv := NewCollector(Paths{DockerSocket: tempSocketPath(t, "missing.sock")}).Docker()
	if inv.Available {
		t.Fatal("Docker inventory available for missing socket")
	}
	if len(inv.Warnings) != 1 {
		t.Fatalf("warnings = %#v", inv.Warnings)
	}
	if !contains(inv.Warnings[0], "docker socket missing: checked") {
		t.Fatalf("warning = %q, want checked socket warning", inv.Warnings[0])
	}
}

func tempSocketPath(t *testing.T, name string) string {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "scrubd-runtime-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir + "/" + name
}

func newUnixHTTPServer(t *testing.T, socketPath string, handler http.Handler) *http.Server {
	t.Helper()

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(socketPath)
	})

	server := &http.Server{Handler: handler}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			t.Errorf("server.Serve: %v", err)
		}
	}()
	return server
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
