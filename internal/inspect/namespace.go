package inspect

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func (c Collector) NetworkNamespaces() ([]NetworkNamespace, []string) {
	var out []NetworkNamespace
	var warnings []string

	netns, err := readNamedNetworkNamespaces(c.paths.NetNSDir)
	if err != nil && !os.IsNotExist(err) {
		warnings = append(warnings, fmt.Sprintf("network namespaces: %v", err))
	}
	out = append(out, netns...)

	procNamespaces, err := readProcessNetworkNamespaces(c.paths.ProcDir)
	if err != nil && !os.IsNotExist(err) {
		warnings = append(warnings, fmt.Sprintf("process network namespaces: %v", err))
	}
	out = append(out, procNamespaces...)

	return out, warnings
}

func readNamedNetworkNamespaces(dir string) ([]NetworkNamespace, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	out := make([]NetworkNamespace, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		out = append(out, NetworkNamespace{
			Path:   path,
			Inode:  namespaceInode(path),
			Source: "netns",
		})
	}
	return out, nil
}

func readProcessNetworkNamespaces(procDir string) ([]NetworkNamespace, error) {
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil, err
	}

	var out []NetworkNamespace
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || !entry.IsDir() {
			continue
		}

		path := filepath.Join(procDir, entry.Name(), "ns", "net")
		inode := namespaceInode(path)
		if inode == "" {
			continue
		}

		out = append(out, NetworkNamespace{
			Path:   path,
			Inode:  inode,
			Source: "process",
			PID:    pid,
		})
	}
	return out, nil
}

func namespaceInode(path string) string {
	target, err := os.Readlink(path)
	if err != nil {
		return ""
	}
	start := strings.IndexByte(target, '[')
	end := strings.IndexByte(target, ']')
	if start == -1 || end == -1 || end <= start+1 {
		return ""
	}
	return target[start+1 : end]
}
