package inspect

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

func (c Collector) Cgroups() ([]Cgroup, []string) {
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
