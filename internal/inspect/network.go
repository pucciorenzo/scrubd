package inspect

import (
	"fmt"
	"net"
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
			HardwareAddr: iface.HardwareAddr.String(),
			Flags:        interfaceFlags(iface.Flags),
			Kind:         interfaceKind(iface.Name),
		})
	}

	return out, nil
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
