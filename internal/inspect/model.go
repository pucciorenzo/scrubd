package inspect

type Inventory struct {
	NetworkInterfaces []NetworkInterface `json:"network_interfaces"`
	Routes            []Route            `json:"routes"`
	FirewallRules     []FirewallRule     `json:"firewall_rules"`
	CNIAllocations    []CNIAllocation    `json:"cni_allocations"`
	CNIStateFiles     []CNIStateFile     `json:"cni_state_files"`
	NetworkNamespaces []NetworkNamespace `json:"network_namespaces"`
	Mounts            []Mount            `json:"mounts"`
	Snapshots         []Snapshot         `json:"snapshots"`
	RuntimeStates     []RuntimeState     `json:"runtime_states"`
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

type FirewallRule struct {
	Backend       string   `json:"backend"`
	Table         string   `json:"table,omitempty"`
	Chain         string   `json:"chain,omitempty"`
	Raw           string   `json:"raw"`
	InterfaceRefs []string `json:"interface_refs,omitempty"`
	Source        string   `json:"source"`
}

type CNIAllocation struct {
	Network     string `json:"network"`
	IP          string `json:"ip"`
	Path        string `json:"path"`
	ContainerID string `json:"container_id,omitempty"`
	Source      string `json:"source"`
}

type CNIStateFile struct {
	Kind        string `json:"kind"`
	Network     string `json:"network,omitempty"`
	ContainerID string `json:"container_id,omitempty"`
	Path        string `json:"path"`
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

type RuntimeState struct {
	Runtime string `json:"runtime"`
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Path    string `json:"path"`
	Source  string `json:"source"`
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
	IPTablesSaveCommand   string
	NFTCommand            string
	CNIStateDir           string
	CNIResultDirs         []string
	NetNSDir              string
	ProcDir               string
	MountInfo             string
	Cgroup                string
	CgroupRoot            string
	DockerOverlayDir      string
	ContainerdSnapshotDir string
	RuntimeStateRoots     []RuntimeStateRoot
}

type RuntimeStateRoot struct {
	Runtime  string
	Kind     string
	Path     string
	MaxDepth int
}

func DefaultPaths() Paths {
	return Paths{
		NetClassDir:           "/sys/class/net",
		ProcNetRoute:          "/proc/net/route",
		IPTablesSaveCommand:   "iptables-save",
		NFTCommand:            "nft",
		CNIStateDir:           "/var/lib/cni/networks",
		CNIResultDirs:         []string{"/var/lib/cni/results", "/var/run/cni/results"},
		NetNSDir:              "/var/run/netns",
		ProcDir:               "/proc",
		MountInfo:             "/proc/self/mountinfo",
		Cgroup:                "/proc/self/cgroup",
		CgroupRoot:            "/sys/fs/cgroup",
		DockerOverlayDir:      "/var/lib/docker/overlay2",
		ContainerdSnapshotDir: "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots",
		RuntimeStateRoots: []RuntimeStateRoot{
			{Runtime: "docker", Kind: "runc_bundle", Path: "/run/docker/runtime-runc/moby", MaxDepth: 1},
			{Runtime: "docker", Kind: "containerd_task", Path: "/run/docker/containerd/daemon/io.containerd.runtime.v2.task/moby", MaxDepth: 1},
			{Runtime: "containerd", Kind: "containerd_task", Path: "/run/containerd/io.containerd.runtime.v2.task", MaxDepth: 2},
			{Runtime: "podman", Kind: "runtime_state", Path: "/run/podman", MaxDepth: 2},
		},
	}
}
