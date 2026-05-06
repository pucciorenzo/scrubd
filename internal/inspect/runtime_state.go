package inspect

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func (c Collector) RuntimeStates() ([]RuntimeState, []string) {
	var states []RuntimeState
	var warnings []string
	for _, root := range c.paths.RuntimeStateRoots {
		found, err := readRuntimeStateRoot(root)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s %s state: %v", root.Runtime, root.Kind, err))
			continue
		}
		states = append(states, found...)
	}
	return states, warnings
}

func readRuntimeStateRoot(root RuntimeStateRoot) ([]RuntimeState, error) {
	if root.Path == "" {
		return nil, nil
	}
	if root.MaxDepth <= 0 {
		root.MaxDepth = 1
	}

	if _, err := os.Stat(root.Path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var states []RuntimeState
	err := walkRuntimeState(root.Path, 0, root.MaxDepth, func(path string) {
		id := filepath.Base(path)
		if !runtimeStateID(id) {
			return
		}
		states = append(states, RuntimeState{
			Runtime: root.Runtime,
			Kind:    root.Kind,
			ID:      id,
			Path:    path,
			Source:  "runtime_state",
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(states, func(i, j int) bool {
		return states[i].Path < states[j].Path
	})
	return states, nil
}

func walkRuntimeState(path string, depth, maxDepth int, visit func(string)) error {
	if depth > 0 {
		visit(path)
	}
	if depth >= maxDepth {
		return nil
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if err := walkRuntimeState(filepath.Join(path, entry.Name()), depth+1, maxDepth, visit); err != nil {
			return err
		}
	}
	return nil
}

func runtimeStateID(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) >= 12 && hexLike(value) {
		return true
	}
	if len(value) == 36 && value[8] == '-' && value[13] == '-' && value[18] == '-' && value[23] == '-' {
		return hexLike(strings.ReplaceAll(value, "-", ""))
	}
	return false
}

func hexLike(value string) bool {
	for _, ch := range value {
		switch {
		case ch >= '0' && ch <= '9':
		case ch >= 'a' && ch <= 'f':
		case ch >= 'A' && ch <= 'F':
		default:
			return false
		}
	}
	return value != ""
}
