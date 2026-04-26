package runtime

type Name string

const (
	NameDocker     Name = "docker"
	NameContainerd Name = "containerd"
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
	DockerSocket     string
	ContainerdSocket string
}

func DefaultPaths() Paths {
	return Paths{
		DockerSocket:     "/var/run/docker.sock",
		ContainerdSocket: "/run/containerd/containerd.sock",
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

func ValidName(name Name) bool {
	switch name {
	case NameAuto, NameDocker, NameContainerd:
		return true
	default:
		return false
	}
}
