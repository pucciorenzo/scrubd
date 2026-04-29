package runtime

import (
	"os"
	"path/filepath"
	"strconv"
)

type Name string

const (
	NameDocker     Name = "docker"
	NameContainerd Name = "containerd"
	NamePodman     Name = "podman"
	NameAuto       Name = "auto"
)

type Inventory struct {
	Runtime    Name        `json:"runtime"`
	Available  bool        `json:"available"`
	Containers []Container `json:"containers,omitempty"`
	Warnings   []string    `json:"warnings,omitempty"`
}

type Container struct {
	ID          string   `json:"id"`
	Names       []string `json:"names,omitempty"`
	Image       string   `json:"image,omitempty"`
	State       string   `json:"state,omitempty"`
	Status      string   `json:"status,omitempty"`
	NetworkMode string   `json:"network_mode,omitempty"`
	PID         int      `json:"pid,omitempty"`
}

type Paths struct {
	DockerSocket      string
	DockerSockets     []string
	ContainerdSocket  string
	ContainerdSockets []string
	PodmanSocket      string
	PodmanSockets     []string
}

func DefaultPaths() Paths {
	return Paths{
		DockerSocket:      "/var/run/docker.sock",
		DockerSockets:     rootlessDockerSockets(os.Getenv("XDG_RUNTIME_DIR"), os.Getuid()),
		ContainerdSocket:  "/run/containerd/containerd.sock",
		ContainerdSockets: rootlessContainerdSockets(os.Getenv("XDG_RUNTIME_DIR"), os.Getuid()),
		PodmanSocket:      "/run/podman/podman.sock",
		PodmanSockets:     rootlessPodmanSockets(os.Getenv("XDG_RUNTIME_DIR"), os.Getuid()),
	}
}

type Collector struct {
	paths Paths
}

func NewCollector(paths Paths) Collector {
	return Collector{paths: paths}
}

func NewDefaultCollector() Collector {
	return NewCollector(DefaultPaths())
}

func (c Collector) dockerSocketCandidates() []string {
	return socketCandidates(c.paths.DockerSocket, c.paths.DockerSockets)
}

func (c Collector) containerdSocketCandidates() []string {
	return socketCandidates(c.paths.ContainerdSocket, c.paths.ContainerdSockets)
}

func (c Collector) podmanSocketCandidates() []string {
	return socketCandidates(c.paths.PodmanSocket, c.paths.PodmanSockets)
}

func socketCandidates(primary string, extra []string) []string {
	values := append([]string{primary}, extra...)
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func rootlessDockerSockets(runtimeDir string, uid int) []string {
	var sockets []string
	if runtimeDir != "" {
		sockets = append(sockets, filepath.Join(runtimeDir, "docker.sock"))
	}
	sockets = append(sockets, filepath.Join("/run/user", strconv.Itoa(uid), "docker.sock"))
	return socketCandidates("", sockets)
}

func rootlessContainerdSockets(runtimeDir string, uid int) []string {
	var sockets []string
	if runtimeDir != "" {
		sockets = append(sockets, filepath.Join(runtimeDir, "containerd", "containerd.sock"))
	}
	sockets = append(sockets, filepath.Join("/run/user", strconv.Itoa(uid), "containerd", "containerd.sock"))
	return socketCandidates("", sockets)
}

func rootlessPodmanSockets(runtimeDir string, uid int) []string {
	var sockets []string
	if runtimeDir != "" {
		sockets = append(sockets, filepath.Join(runtimeDir, "podman", "podman.sock"))
	}
	sockets = append(sockets, filepath.Join("/run/user", strconv.Itoa(uid), "podman", "podman.sock"))
	return socketCandidates("", sockets)
}

func ValidName(name Name) bool {
	switch name {
	case NameAuto, NameDocker, NameContainerd, NamePodman:
		return true
	default:
		return false
	}
}
