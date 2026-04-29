package inspect

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

func (c Collector) CNIAllocations() ([]CNIAllocation, []string) {
	if c.paths.CNIStateDir == "" {
		return nil, nil
	}

	allocations, err := readCNIAllocations(c.paths.CNIStateDir)
	if err != nil {
		return nil, []string{fmt.Sprintf("cni allocations: %v", err)}
	}
	return allocations, nil
}

func readCNIAllocations(root string) ([]CNIAllocation, error) {
	networkDirs, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var allocations []CNIAllocation
	for _, networkDir := range networkDirs {
		if !networkDir.IsDir() {
			continue
		}
		network := networkDir.Name()
		entries, err := os.ReadDir(filepath.Join(root, network))
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if entry.IsDir() || net.ParseIP(entry.Name()) == nil {
				continue
			}
			path := filepath.Join(root, network, entry.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			allocations = append(allocations, CNIAllocation{
				Network:     network,
				IP:          entry.Name(),
				Path:        path,
				ContainerID: strings.TrimSpace(string(data)),
				Source:      "cni_ipam",
			})
		}
	}
	return allocations, nil
}
