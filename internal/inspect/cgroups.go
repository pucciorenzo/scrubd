package inspect

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func (c Collector) Cgroups() ([]Cgroup, []string) {
	if c.paths.CgroupRoot != "" {
		cgroups, warnings, err := scanCgroupRoot(c.paths.CgroupRoot)
		if err == nil {
			return cgroups, warnings
		}
		if !os.IsNotExist(err) {
			return nil, append(warnings, fmt.Sprintf("cgroup root: %v", err))
		}
	}

	file, err := os.Open(c.paths.Cgroup)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, []string{fmt.Sprintf("cgroup: %v", err)}
	}
	defer file.Close()

	cgroups, err := parseCgroups(file)
	if err != nil {
		return nil, []string{fmt.Sprintf("cgroup: %v", err)}
	}
	return cgroups, nil
}

func scanCgroupRoot(root string) ([]Cgroup, []string, error) {
	var cgroups []Cgroup
	var warnings []string

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("cgroup %s: %v", path, err))
			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.IsDir() || path == root {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("cgroup %s: %v", path, err))
			return filepath.SkipDir
		}
		cgroupPath := "/" + filepath.ToSlash(rel)
		if !runtimeCgroupPath(cgroupPath) {
			return nil
		}
		processCount, processCountKnown, err := readCgroupProcessCount(path)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("cgroup %s processes: %v", path, err))
		}

		cgroups = append(cgroups, Cgroup{
			HierarchyID:       "0",
			Path:              cgroupPath,
			ProcessCount:      processCount,
			ProcessCountKnown: processCountKnown,
		})
		return nil
	})
	if err != nil {
		return cgroups, warnings, err
	}
	return cgroups, warnings, nil
}

func readCgroupProcessCount(path string) (int, bool, error) {
	file, err := os.Open(filepath.Join(path, "cgroup.procs"))
	if err != nil {
		if os.IsNotExist(err) {
			return 0, false, nil
		}
		return 0, false, err
	}
	defer file.Close()

	var count int
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, false, err
	}
	return count, true, nil
}

func parseCgroups(file io.Reader) ([]Cgroup, error) {
	var cgroups []Cgroup
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		cgroup, ok := parseCgroupLine(scanner.Text())
		if !ok {
			return nil, fmt.Errorf("invalid line %q", scanner.Text())
		}
		cgroups = append(cgroups, cgroup)
	}
	return cgroups, scanner.Err()
}

func parseCgroupLine(line string) (Cgroup, bool) {
	fields := strings.SplitN(line, ":", 3)
	if len(fields) != 3 {
		return Cgroup{}, false
	}

	return Cgroup{
		HierarchyID: fields[0],
		Controllers: splitComma(fields[1]),
		Path:        fields[2],
	}, true
}

func runtimeCgroupPath(path string) bool {
	path = strings.ToLower(path)
	if strings.Contains(path, "kubepods") {
		return strings.Contains(path, "/pod")
	}
	return strings.Contains(path, "docker") ||
		strings.Contains(path, "containerd") ||
		strings.Contains(path, "libpod")
}
