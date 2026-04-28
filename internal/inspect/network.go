package inspect

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
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
		out = append(out, NetworkInterface{
			Name:         iface.Name,
			Index:        iface.Index,
			PeerIndex:    c.interfacePeerIndex(iface),
			HardwareAddr: iface.HardwareAddr.String(),
			Flags:        interfaceFlags(iface.Flags),
			Kind:         interfaceKind(iface.Name),
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

func interfaceKind(name string) string {
	switch {
	case strings.HasPrefix(name, "veth"):
		return "veth"
	case strings.HasPrefix(name, "br-"), name == "docker0", strings.HasPrefix(name, "cni"):
		return "bridge"
	default:
		return "unknown"
	}
}
