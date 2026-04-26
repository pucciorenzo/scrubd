package runtime

func parseCRIListContainersResponse(data []byte) []Container {
	var containers []Container
	for len(data) > 0 {
		field, wire, rest, ok := consumeProtoKey(data)
		if !ok {
			break
		}
		data = rest
		switch {
		case field == 1 && wire == 2:
			value, rest, ok := consumeProtoBytes(data)
			if !ok {
				return containers
			}
			containers = append(containers, parseCRIContainer(value))
			data = rest
		default:
			rest, ok := skipProtoValue(data, wire)
			if !ok {
				return containers
			}
			data = rest
		}
	}
	return containers
}

func parseCRIContainer(data []byte) Container {
	var container Container
	for len(data) > 0 {
		field, wire, rest, ok := consumeProtoKey(data)
		if !ok {
			break
		}
		data = rest
		switch {
		case field == 1 && wire == 2:
			value, rest, ok := consumeProtoBytes(data)
			if !ok {
				return container
			}
			container.ID = string(value)
			data = rest
		case field == 3 && wire == 2:
			value, rest, ok := consumeProtoBytes(data)
			if !ok {
				return container
			}
			name := parseCRIMetadataName(value)
			if name != "" {
				container.Names = []string{name}
			}
			data = rest
		case field == 4 && wire == 2:
			value, rest, ok := consumeProtoBytes(data)
			if !ok {
				return container
			}
			container.Image = parseCRIImageName(value)
			data = rest
		case field == 6 && wire == 0:
			state, rest, ok := consumeProtoVarint(data)
			if !ok {
				return container
			}
			container.State = criStateName(state)
			container.Status = container.State
			data = rest
		default:
			rest, ok := skipProtoValue(data, wire)
			if !ok {
				return container
			}
			data = rest
		}
	}
	return container
}

func parseCRIMetadataName(data []byte) string {
	for len(data) > 0 {
		field, wire, rest, ok := consumeProtoKey(data)
		if !ok {
			break
		}
		data = rest
		if field == 1 && wire == 2 {
			value, _, ok := consumeProtoBytes(data)
			if ok {
				return string(value)
			}
			return ""
		}
		rest, ok = skipProtoValue(data, wire)
		if !ok {
			return ""
		}
		data = rest
	}
	return ""
}

func parseCRIImageName(data []byte) string {
	for len(data) > 0 {
		field, wire, rest, ok := consumeProtoKey(data)
		if !ok {
			break
		}
		data = rest
		if field == 1 && wire == 2 {
			value, _, ok := consumeProtoBytes(data)
			if ok {
				return string(value)
			}
			return ""
		}
		rest, ok = skipProtoValue(data, wire)
		if !ok {
			return ""
		}
		data = rest
	}
	return ""
}

func criStateName(state uint64) string {
	switch state {
	case 0:
		return "created"
	case 1:
		return "running"
	case 2:
		return "exited"
	default:
		return "unknown"
	}
}

func consumeProtoKey(data []byte) (field uint64, wire uint64, rest []byte, ok bool) {
	key, rest, ok := consumeProtoVarint(data)
	if !ok {
		return 0, 0, nil, false
	}
	return key >> 3, key & 0x7, rest, true
}

func consumeProtoBytes(data []byte) ([]byte, []byte, bool) {
	size, rest, ok := consumeProtoVarint(data)
	if !ok || size > uint64(len(rest)) {
		return nil, nil, false
	}
	return rest[:size], rest[size:], true
}

func consumeProtoVarint(data []byte) (uint64, []byte, bool) {
	var value uint64
	for i, b := range data {
		if i == 10 {
			return 0, nil, false
		}
		value |= uint64(b&0x7f) << (7 * i)
		if b < 0x80 {
			return value, data[i+1:], true
		}
	}
	return 0, nil, false
}

func skipProtoValue(data []byte, wire uint64) ([]byte, bool) {
	switch wire {
	case 0:
		_, rest, ok := consumeProtoVarint(data)
		return rest, ok
	case 1:
		if len(data) < 8 {
			return nil, false
		}
		return data[8:], true
	case 2:
		_, rest, ok := consumeProtoBytes(data)
		return rest, ok
	case 5:
		if len(data) < 4 {
			return nil, false
		}
		return data[4:], true
	default:
		return nil, false
	}
}
