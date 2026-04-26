package inspect

type Collector struct {
	paths Paths
}

func NewCollector(paths Paths) Collector {
	return Collector{paths: paths}
}

func NewDefaultCollector() Collector {
	return NewCollector(DefaultPaths())
}

func (c Collector) Inventory() Inventory {
	var inv Inventory

	addWarnings := func(warnings []string) {
		inv.Warnings = append(inv.Warnings, warnings...)
	}

	interfaces, warnings := c.NetworkInterfaces()
	inv.NetworkInterfaces = interfaces
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

	cgroups, warnings := c.Cgroups()
	inv.Cgroups = cgroups
	addWarnings(warnings)

	processes, warnings := c.Processes()
	inv.Processes = processes
	addWarnings(warnings)

	return inv
}
