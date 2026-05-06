package inspect

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
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

func (c Collector) CNIStateFiles() ([]CNIStateFile, []string) {
	if len(c.paths.CNIResultDirs) == 0 {
		return nil, nil
	}

	var out []CNIStateFile
	var warnings []string
	for _, root := range c.paths.CNIResultDirs {
		files, err := readCNIStateFiles(root)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("cni state files: %s: %v", root, err))
			continue
		}
		out = append(out, files...)
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].Path < out[j].Path
	})
	return out, warnings
}

func readCNIStateFiles(root string) ([]CNIStateFile, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var out []CNIStateFile
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join(root, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		state := parseCNIStateFile(path, data)
		if state.ContainerID == "" {
			continue
		}
		out = append(out, state)
	}
	return out, nil
}

func parseCNIStateFile(path string, data []byte) CNIStateFile {
	state := CNIStateFile{
		Kind:   "cni_result",
		Path:   path,
		Source: "cni_result_cache",
	}

	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return state
	}

	if kind := findJSONString(value, "kind"); kind != "" {
		state.Kind = kind
	}
	state.Network = firstNonEmptyString(
		findJSONString(value, "networkName"),
		findJSONString(value, "network_name"),
		findJSONString(value, "name"),
	)
	state.ContainerID = firstNonEmptyString(
		findJSONString(value, "containerId"),
		findJSONString(value, "containerID"),
		findJSONString(value, "container_id"),
	)
	return state
}

func findJSONString(value any, key string) string {
	switch typed := value.(type) {
	case map[string]any:
		for k, v := range typed {
			if strings.EqualFold(k, key) {
				if s, ok := v.(string); ok {
					return strings.TrimSpace(s)
				}
			}
		}
		for _, v := range typed {
			if s := findJSONString(v, key); s != "" {
				return s
			}
		}
	case []any:
		for _, v := range typed {
			if s := findJSONString(v, key); s != "" {
				return s
			}
		}
	}
	return ""
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
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
