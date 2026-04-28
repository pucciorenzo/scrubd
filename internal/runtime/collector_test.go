package runtime

import (
	"fmt"
	"net/http"
	"testing"
)

func TestInventoriesSelectsRequestedRuntime(t *testing.T) {
	dockerSocket := tempSocketPath(t, "docker.sock")
	dockerServer := newUnixHTTPServer(t, dockerSocket, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/containers/json":
			fmt.Fprint(w, `[{"Id":"docker123","Names":["/web"],"State":"running"}]`)
		case "/containers/docker123/json":
			fmt.Fprint(w, `{"State":{"Pid":4321}}`)
		default:
			t.Fatalf("docker path = %q", r.URL.Path)
		}
	}))
	defer dockerServer.Close()

	containerdSocket := tempSocketPath(t, "containerd.sock")
	containerdServer := newRawGRPCServer(t, containerdSocket, buildCRIListContainersResponse(
		buildCRIContainer("containerd123", "job", "busybox:latest", 1),
	))
	defer containerdServer.Stop()

	collector := NewCollector(Paths{
		DockerSocket:     dockerSocket,
		ContainerdSocket: containerdSocket,
	})

	dockerOnly := collector.Inventories(NameDocker)
	if len(dockerOnly) != 1 || dockerOnly[0].Runtime != NameDocker || !dockerOnly[0].Available {
		t.Fatalf("docker inventories = %#v, want one available docker inventory", dockerOnly)
	}

	containerdOnly := collector.Inventories(NameContainerd)
	if len(containerdOnly) != 1 || containerdOnly[0].Runtime != NameContainerd || !containerdOnly[0].Available {
		t.Fatalf("containerd inventories = %#v, want one available containerd inventory", containerdOnly)
	}

	auto := collector.Inventories(NameAuto)
	if len(auto) != 2 {
		t.Fatalf("auto inventories = %#v, want two inventories", auto)
	}
	if auto[0].Runtime != NameDocker || !auto[0].Available {
		t.Fatalf("auto docker inventory = %#v, want available docker first", auto[0])
	}
	if auto[1].Runtime != NameContainerd || !auto[1].Available {
		t.Fatalf("auto containerd inventory = %#v, want available containerd second", auto[1])
	}
}
