package inspect

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

func (c Collector) Routes() ([]Route, []string) {
	if c.paths.ProcNetRoute == "" {
		return nil, nil
	}
	file, err := os.Open(c.paths.ProcNetRoute)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, []string{fmt.Sprintf("routes: %v", err)}
	}
	defer file.Close()

	routes, err := parseProcNetRoute(file)
	if err != nil {
		return nil, []string{fmt.Sprintf("routes: %v", err)}
	}
	return routes, nil
}

func parseProcNetRoute(input io.Reader) ([]Route, error) {
	scanner := bufio.NewScanner(input)
	if !scanner.Scan() {
		return nil, scanner.Err()
	}

	var routes []Route
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		route, err := parseProcNetRouteLine(line)
		if err != nil {
			return nil, err
		}
		routes = append(routes, route)
	}
	return routes, scanner.Err()
}

func parseProcNetRouteLine(line string) (Route, error) {
	fields := strings.Fields(line)
	if len(fields) < 8 {
		return Route{}, fmt.Errorf("invalid route line %q", line)
	}

	destination, err := parseRouteIPv4(fields[1])
	if err != nil {
		return Route{}, fmt.Errorf("destination %q: %w", fields[1], err)
	}
	gateway, err := parseRouteIPv4(fields[2])
	if err != nil {
		return Route{}, fmt.Errorf("gateway %q: %w", fields[2], err)
	}
	mask, err := parseRouteIPv4(fields[7])
	if err != nil {
		return Route{}, fmt.Errorf("mask %q: %w", fields[7], err)
	}

	return Route{
		Interface:   fields[0],
		Destination: destination,
		Gateway:     gateway,
		Flags:       fields[3],
		Mask:        mask,
		Source:      "proc_net_route",
	}, nil
}

func parseRouteIPv4(value string) (string, error) {
	raw, err := strconv.ParseUint(value, 16, 32)
	if err != nil {
		return "", err
	}
	var bytes [4]byte
	binary.LittleEndian.PutUint32(bytes[:], uint32(raw))
	return net.IPv4(bytes[0], bytes[1], bytes[2], bytes[3]).String(), nil
}
