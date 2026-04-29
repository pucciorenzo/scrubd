package inspect

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func (c Collector) NetworkInterfaces() ([]NetworkInterface, []string) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, []string{fmt.Sprintf("network interfaces: %v", err)}
	}

	out := make([]NetworkInterface, 0, len(interfaces))
	for _, iface := range interfaces {
		bridgePorts, bridgePortsKnown := c.interfaceBridgePorts(iface.Name)
		out = append(out, NetworkInterface{
			Name:             iface.Name,
			Index:            iface.Index,
			PeerIndex:        c.interfacePeerIndex(iface),
			HardwareAddr:     iface.HardwareAddr.String(),
			Flags:            interfaceFlags(iface.Flags),
			Kind:             c.interfaceKind(iface.Name),
			BridgePorts:      bridgePorts,
			BridgePortsKnown: bridgePortsKnown,
		})
	}

	return out, nil
}

func (c Collector) interfacePeerIndex(iface net.Interface) int {
	if c.paths.NetClassDir == "" {
		return 0
	}
	data, err := os.ReadFile(filepath.Join(c.paths.NetClassDir, iface.Name, "iflink"))
	if err != nil {
		return 0
	}
	peerIndex, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || peerIndex == iface.Index {
		return 0
	}
	return peerIndex
}

func interfaceFlags(flags net.Flags) []string {
	var out []string
	for _, item := range []struct {
		flag net.Flags
		name string
	}{
		{net.FlagUp, "up"},
		{net.FlagBroadcast, "broadcast"},
		{net.FlagLoopback, "loopback"},
		{net.FlagPointToPoint, "point_to_point"},
		{net.FlagMulticast, "multicast"},
		{net.FlagRunning, "running"},
	} {
		if flags&item.flag != 0 {
			out = append(out, item.name)
		}
	}
	return out
}

func (c Collector) interfaceKind(name string) string {
	if c.paths.NetClassDir != "" {
		if _, err := os.Stat(filepath.Join(c.paths.NetClassDir, name, "bridge")); err == nil {
			return "bridge"
		}
	}
	switch {
	case strings.HasPrefix(name, "veth"):
		return "veth"
	case strings.HasPrefix(name, "br-"), name == "docker0", strings.HasPrefix(name, "cni"), strings.HasPrefix(name, "podman"):
		return "bridge"
	default:
		return "unknown"
	}
}

func (c Collector) interfaceBridgePorts(name string) ([]string, bool) {
	if c.paths.NetClassDir == "" {
		return nil, false
	}
	entries, err := os.ReadDir(filepath.Join(c.paths.NetClassDir, name, "brif"))
	if err != nil {
		return nil, false
	}

	ports := make([]string, 0, len(entries))
	for _, entry := range entries {
		ports = append(ports, entry.Name())
	}
	sort.Strings(ports)
	return ports, true
}
