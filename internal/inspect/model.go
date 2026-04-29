package inspect

type Inventory struct {
	NetworkInterfaces []NetworkInterface `json:"network_interfaces"`
	Routes            []Route            `json:"routes"`
	NetworkNamespaces []NetworkNamespace `json:"network_namespaces"`
	Mounts            []Mount            `json:"mounts"`
	Snapshots         []Snapshot         `json:"snapshots"`
	Cgroups           []Cgroup           `json:"cgroups"`
	Processes         []Process          `json:"processes"`
	Warnings          []string           `json:"warnings,omitempty"`
}

type NetworkInterface struct {
	Name             string   `json:"name"`
	Index            int      `json:"index"`
	PeerIndex        int      `json:"peer_index,omitempty"`
	HardwareAddr     string   `json:"hardware_addr,omitempty"`
	Flags            []string `json:"flags,omitempty"`
	Kind             string   `json:"kind,omitempty"`
	BridgePorts      []string `json:"bridge_ports,omitempty"`
	BridgePortsKnown bool     `json:"bridge_ports_known,omitempty"`
}

type Route struct {
	Interface   string `json:"interface"`
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	Flags       string `json:"flags,omitempty"`
	Mask        string `json:"mask,omitempty"`
	Source      string `json:"source"`
}

type NetworkNamespace struct {
	Path   string `json:"path"`
	Inode  string `json:"inode,omitempty"`
	Source string `json:"source"`
	PID    int    `json:"pid,omitempty"`
}

type Mount struct {
	ID         string   `json:"id"`
	ParentID   string   `json:"parent_id"`
	MajorMinor string   `json:"major_minor"`
	Root       string   `json:"root"`
	MountPoint string   `json:"mount_point"`
	Options    []string `json:"options,omitempty"`
	FSType     string   `json:"fs_type"`
	Source     string   `json:"source"`
	SuperOpts  []string `json:"super_options,omitempty"`
}

type Snapshot struct {
	Runtime string `json:"runtime"`
	ID      string `json:"id"`
	Path    string `json:"path"`
}

type Cgroup struct {
	HierarchyID       string   `json:"hierarchy_id"`
	Controllers       []string `json:"controllers,omitempty"`
	Path              string   `json:"path"`
	ProcessCount      int      `json:"process_count"`
	ProcessCountKnown bool     `json:"process_count_known"`
}

type Process struct {
	PID     int      `json:"pid"`
	Command string   `json:"command,omitempty"`
	Args    []string `json:"args,omitempty"`
}

type Paths struct {
	NetClassDir           string
	ProcNetRoute          string
	NetNSDir              string
	ProcDir               string
	MountInfo             string
	Cgroup                string
	CgroupRoot            string
	DockerOverlayDir      string
	ContainerdSnapshotDir string
}

func DefaultPaths() Paths {
	return Paths{
		NetClassDir:           "/sys/class/net",
		ProcNetRoute:          "/proc/net/route",
		NetNSDir:              "/var/run/netns",
		ProcDir:               "/proc",
		MountInfo:             "/proc/self/mountinfo",
		Cgroup:                "/proc/self/cgroup",
		CgroupRoot:            "/sys/fs/cgroup",
		DockerOverlayDir:      "/var/lib/docker/overlay2",
		ContainerdSnapshotDir: "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots",
	}
}
