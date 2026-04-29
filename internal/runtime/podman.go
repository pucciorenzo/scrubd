package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"time"
)

func (c Collector) Podman() Inventory {
	inv := Inventory{Runtime: NamePodman}
	candidates := c.podmanSocketCandidates()
	if len(candidates) == 0 {
		inv.Warnings = append(inv.Warnings, "podman socket path not configured")
		return inv
	}
	var missing []string
	for _, socketPath := range candidates {
		if _, err := os.Stat(socketPath); err != nil {
			if os.IsNotExist(err) {
				missing = append(missing, socketPath)
			} else {
				inv.Warnings = append(inv.Warnings, socketStatWarning("podman", socketPath, err))
			}
			continue
		}

		client := podmanHTTPClient(socketPath)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		var containers []podmanContainer
		err := podmanGetJSON(ctx, client, "/containers/json?all=true", &containers)
		cancel()
		if err != nil {
			inv.Warnings = append(inv.Warnings, podmanAPIWarning(socketPath, err))
			continue
		}

		inv.Available = true
		inv.Containers = make([]Container, 0, len(containers))
		for _, container := range containers {
			normalized := container.toContainer()
			if container.ID != "" {
				var details podmanContainerInspect
				path := fmt.Sprintf("/containers/%s/json", container.ID)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				err := podmanGetJSON(ctx, client, path, &details)
				cancel()
				if err != nil {
					inv.Warnings = append(inv.Warnings, fmt.Sprintf("podman inspect %s: %v", shortID(container.ID), err))
				} else {
					normalized.PID = details.State.PID
				}
			}
			inv.Containers = append(inv.Containers, normalized)
		}
		return inv
	}
	if len(inv.Warnings) == 0 && len(missing) > 0 {
		inv.Warnings = append(inv.Warnings, socketsMissingWarning("podman", missing))
	}
	return inv
}

func podmanGetJSON(ctx context.Context, client *http.Client, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://podman"+path, nil)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("status %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return nil
}

func podmanHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var dialer net.Dialer
				return dialer.DialContext(ctx, "unix", socketPath)
			},
		},
	}
}

type podmanContainer struct {
	ID              string             `json:"Id"`
	Names           []string           `json:"Names"`
	Image           string             `json:"Image"`
	State           string             `json:"State"`
	Status          string             `json:"Status"`
	NetworkSettings podmanNetworkInfo  `json:"NetworkSettings"`
	Networks        map[string]unknown `json:"Networks"`
}

type podmanNetworkInfo struct {
	Networks map[string]unknown `json:"Networks"`
}

type unknown struct{}

type podmanContainerInspect struct {
	State podmanContainerState `json:"State"`
}

type podmanContainerState struct {
	PID int `json:"Pid"`
}

func (c podmanContainer) toContainer() Container {
	return Container{
		ID:          c.ID,
		Names:       trimDockerNames(c.Names),
		Image:       c.Image,
		State:       c.State,
		Status:      c.Status,
		NetworkMode: firstPodmanNetwork(c.NetworkSettings.Networks, c.Networks),
	}
}

func firstPodmanNetwork(networkSettings map[string]unknown, networks map[string]unknown) string {
	if len(networkSettings) > 0 {
		return firstNetworkName(networkSettings)
	}
	return firstNetworkName(networks)
}

func firstNetworkName[T any](networks map[string]T) string {
	names := make([]string, 0, len(networks))
	for name := range networks {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return ""
	}
	return names[0]
}
