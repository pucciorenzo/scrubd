package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

func (c Collector) Docker() Inventory {
	inv := Inventory{Runtime: NameDocker}
	candidates := c.dockerSocketCandidates()
	if len(candidates) == 0 {
		inv.Warnings = append(inv.Warnings, "docker socket path not configured")
		return inv
	}
	var missing []string
	for _, socketPath := range candidates {
		if _, err := os.Stat(socketPath); err != nil {
			if os.IsNotExist(err) {
				missing = append(missing, socketPath)
			} else {
				inv.Warnings = append(inv.Warnings, socketStatWarning("docker", socketPath, err))
			}
			continue
		}

		client := dockerHTTPClient(socketPath)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		var containers []dockerContainer
		err := dockerGetJSON(ctx, client, "/containers/json?all=true", &containers)
		cancel()
		if err != nil {
			inv.Warnings = append(inv.Warnings, dockerAPIWarning(socketPath, err))
			continue
		}

		inv.Available = true
		inv.Containers = make([]Container, 0, len(containers))
		for _, container := range containers {
			normalized := container.toContainer()
			if container.ID != "" {
				var details dockerContainerInspect
				path := fmt.Sprintf("/containers/%s/json", container.ID)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				err := dockerGetJSON(ctx, client, path, &details)
				cancel()
				if err != nil {
					inv.Warnings = append(inv.Warnings, fmt.Sprintf("docker inspect %s: %v", shortID(container.ID), err))
				} else {
					normalized.PID = details.State.PID
				}
			}
			inv.Containers = append(inv.Containers, normalized)
		}
		return inv
	}
	if len(inv.Warnings) == 0 && len(missing) > 0 {
		inv.Warnings = append(inv.Warnings, socketsMissingWarning("docker", missing))
	}
	return inv
}

func dockerGetJSON(ctx context.Context, client *http.Client, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
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

func dockerHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var dialer net.Dialer
				return dialer.DialContext(ctx, "unix", socketPath)
			},
		},
	}
}

type dockerContainer struct {
	ID              string            `json:"Id"`
	Names           []string          `json:"Names"`
	Image           string            `json:"Image"`
	State           string            `json:"State"`
	Status          string            `json:"Status"`
	NetworkSettings dockerNetworkInfo `json:"NetworkSettings"`
}

type dockerNetworkInfo struct {
	Networks map[string]dockerEndpoint `json:"Networks"`
}

type dockerEndpoint struct {
	NetworkID string `json:"NetworkID"`
}

type dockerContainerInspect struct {
	State dockerContainerState `json:"State"`
}

type dockerContainerState struct {
	PID int `json:"Pid"`
}

func (c dockerContainer) toContainer() Container {
	return Container{
		ID:          c.ID,
		Names:       trimDockerNames(c.Names),
		Image:       c.Image,
		State:       c.State,
		Status:      c.Status,
		NetworkMode: firstDockerNetwork(c.NetworkSettings.Networks),
	}
}

func trimDockerNames(names []string) []string {
	out := make([]string, 0, len(names))
	for _, name := range names {
		if len(name) > 0 && name[0] == '/' {
			name = name[1:]
		}
		out = append(out, name)
	}
	return out
}

func firstDockerNetwork(networks map[string]dockerEndpoint) string {
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

func shortID(id string) string {
	id = strings.TrimSpace(id)
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
