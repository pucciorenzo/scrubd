package inspect

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type Collector struct {
	paths      Paths
	runCommand commandRunner
}

func NewCollector(paths Paths) Collector {
	return Collector{paths: paths, runCommand: defaultCommandRunner}
}

func NewDefaultCollector() Collector {
	return NewCollector(DefaultPaths())
}

func (c Collector) Inventory() Inventory {
	return c.inventory(runtime.GOOS)
}

func (c Collector) inventory(goos string) Inventory {
	if goos != "linux" {
		return Inventory{
			Warnings: []string{
				fmt.Sprintf("host inspection unsupported on %s: scrubd must run on Linux to inspect container runtime resources", goos),
			},
		}
	}

	var inv Inventory

	addWarnings := func(warnings []string) {
		inv.Warnings = append(inv.Warnings, warnings...)
	}

	interfaces, warnings := c.NetworkInterfaces()
	inv.NetworkInterfaces = interfaces
	addWarnings(warnings)

	routes, warnings := c.Routes()
	inv.Routes = routes
	addWarnings(warnings)

	firewallRules, warnings := c.FirewallRules()
	inv.FirewallRules = firewallRules
	addWarnings(warnings)

	allocations, warnings := c.CNIAllocations()
	inv.CNIAllocations = allocations
	addWarnings(warnings)

	namespaces, warnings := c.NetworkNamespaces()
	inv.NetworkNamespaces = namespaces
	addWarnings(warnings)

	mounts, warnings := c.Mounts()
	inv.Mounts = mounts
	addWarnings(warnings)

	snapshots, warnings := c.Snapshots()
	inv.Snapshots = snapshots
	addWarnings(warnings)

	states, warnings := c.RuntimeStates()
	inv.RuntimeStates = states
	addWarnings(warnings)

	cgroups, warnings := c.Cgroups()
	inv.Cgroups = cgroups
	addWarnings(warnings)

	processes, warnings := c.Processes()
	inv.Processes = processes
	addWarnings(warnings)

	return inv
}

type commandRunner func(name string, args ...string) ([]byte, error)

func defaultCommandRunner(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if errors.Is(err, exec.ErrNotFound) {
		return nil, err
	}
	if ctx.Err() != nil {
		return output, ctx.Err()
	}
	if err != nil && len(output) > 0 {
		return output, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return output, err
}
