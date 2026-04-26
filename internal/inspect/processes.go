package inspect

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func (c Collector) Processes() ([]Process, []string) {
	processes, err := readProcesses(c.paths.ProcDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, []string{fmt.Sprintf("processes: %v", err)}
	}
	return processes, nil
}

func readProcesses(procDir string) ([]Process, error) {
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil, err
	}

	var out []Process
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || !entry.IsDir() {
			continue
		}

		process := Process{PID: pid}
		process.Command = readTrimmed(filepath.Join(procDir, entry.Name(), "comm"))
		process.Args = readCmdline(filepath.Join(procDir, entry.Name(), "cmdline"))
		out = append(out, process)
	}
	return out, nil
}

func readTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readCmdline(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return nil
	}

	raw := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
	args := raw[:0]
	for _, arg := range raw {
		if arg != "" {
			args = append(args, arg)
		}
	}
	return args
}
