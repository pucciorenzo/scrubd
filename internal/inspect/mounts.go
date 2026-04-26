package inspect

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

func (c Collector) Mounts() ([]Mount, []string) {
	file, err := os.Open(c.paths.MountInfo)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, []string{fmt.Sprintf("mountinfo: %v", err)}
	}
	defer file.Close()

	mounts, err := parseMountInfo(file)
	if err != nil {
		return nil, []string{fmt.Sprintf("mountinfo: %v", err)}
	}
	return mounts, nil
}

func parseMountInfo(input io.Reader) ([]Mount, error) {
	var mounts []Mount
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := scanner.Text()
		mount, ok := parseMountInfoLine(line)
		if !ok {
			return nil, fmt.Errorf("invalid line %q", line)
		}
		mounts = append(mounts, mount)
	}
	return mounts, scanner.Err()
}

func parseMountInfoLine(line string) (Mount, bool) {
	before, after, ok := strings.Cut(line, " - ")
	if !ok {
		return Mount{}, false
	}

	fields := strings.Fields(before)
	super := strings.Fields(after)
	if len(fields) < 6 || len(super) < 3 {
		return Mount{}, false
	}

	return Mount{
		ID:         fields[0],
		ParentID:   fields[1],
		MajorMinor: fields[2],
		Root:       unescapeMountField(fields[3]),
		MountPoint: unescapeMountField(fields[4]),
		Options:    splitComma(fields[5]),
		FSType:     super[0],
		Source:     super[1],
		SuperOpts:  splitComma(super[2]),
	}, true
}

func unescapeMountField(value string) string {
	value = strings.ReplaceAll(value, `\040`, " ")
	value = strings.ReplaceAll(value, `\011`, "\t")
	value = strings.ReplaceAll(value, `\012`, "\n")
	value = strings.ReplaceAll(value, `\134`, `\`)
	return value
}

func splitComma(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}
