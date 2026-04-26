package runtime

func (c Collector) Inventories(name Name) []Inventory {
	switch name {
	case NameDocker:
		return []Inventory{c.Docker()}
	case NameContainerd:
		return []Inventory{c.Containerd()}
	case NameAuto:
		return []Inventory{c.Docker(), c.Containerd()}
	default:
		return []Inventory{{
			Runtime:  name,
			Warnings: []string{"unknown runtime"},
		}}
	}
}
