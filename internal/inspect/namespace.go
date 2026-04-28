package inspect

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func (c Collector) NetworkNamespaces() ([]NetworkNamespace, []string) {
	var out []NetworkNamespace
	var warnings []string

	netns, netnsWarnings, err := readNamedNetworkNamespaces(c.paths.NetNSDir)
	if err != nil && !os.IsNotExist(err) {
		warnings = append(warnings, fmt.Sprintf("network namespaces: %v", err))
	}
	warnings = append(warnings, netnsWarnings...)
	out = append(out, netns...)

	procNamespaces, procWarnings, err := readProcessNetworkNamespaces(c.paths.ProcDir)
	if err != nil && !os.IsNotExist(err) {
		warnings = append(warnings, fmt.Sprintf("process network namespaces: %v", err))
	}
	warnings = append(warnings, procWarnings...)
	out = append(out, procNamespaces...)

	return out, warnings
}

func readNamedNetworkNamespaces(dir string) ([]NetworkNamespace, []string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}

	out := make([]NetworkNamespace, 0, len(entries))
	var warnings []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		inode, err := namespaceInode(path)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("network namespace %s: %v", path, err))
			continue
		}
		out = append(out, NetworkNamespace{
			Path:   path,
			Inode:  inode,
			Source: "netns",
		})
	}
	return out, warnings, nil
}

func readProcessNetworkNamespaces(procDir string) ([]NetworkNamespace, []string, error) {
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil, nil, err
	}

	var out []NetworkNamespace
	var warnings []string
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || !entry.IsDir() {
			continue
		}

		path := filepath.Join(procDir, entry.Name(), "ns", "net")
		inode, err := namespaceInode(path)
		if err != nil {
			if !os.IsNotExist(err) {
				warnings = append(warnings, fmt.Sprintf("process network namespace %s: %v", path, err))
			}
			continue
		}

		out = append(out, NetworkNamespace{
			Path:   path,
			Inode:  inode,
			Source: "process",
			PID:    pid,
		})
	}
	return out, warnings, nil
}

func namespaceInode(path string) (string, error) {
	target, err := os.Readlink(path)
	if err != nil {
		return statInode(path)
	}
	start := strings.IndexByte(target, '[')
	end := strings.IndexByte(target, ']')
	if start == -1 || end == -1 || end <= start+1 {
		return "", fmt.Errorf("invalid namespace link target %q", target)
	}
	return target[start+1 : end], nil
}

func statInode(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("stat inode unavailable")
	}
	return strconv.FormatUint(stat.Ino, 10), nil
}
