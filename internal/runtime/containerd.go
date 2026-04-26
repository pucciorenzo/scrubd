package runtime

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func (c Collector) Containerd() Inventory {
	inv := Inventory{Runtime: NameContainerd}
	if _, err := os.Stat(c.paths.ContainerdSocket); err != nil {
		inv.Warnings = append(inv.Warnings, fmt.Sprintf("containerd socket unavailable: %v", err))
		return inv
	}

	conn, err := net.DialTimeout("unix", c.paths.ContainerdSocket, 2*time.Second)
	if err != nil {
		inv.Warnings = append(inv.Warnings, fmt.Sprintf("containerd socket connect: %v", err))
		return inv
	}
	_ = conn.Close()

	inv.Available = true
	containers, err := listContainerdCRIContainers(c.paths.ContainerdSocket)
	if err != nil {
		inv.Warnings = append(inv.Warnings, fmt.Sprintf("containerd CRI inventory: %v", err))
		return inv
	}
	inv.Containers = containers
	return inv
}

func listContainerdCRIContainers(socketPath string) ([]Container, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawProtoCodec{})),
	)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	methods := []string{
		"/runtime.v1.RuntimeService/ListContainers",
		"/runtime.v1alpha2.RuntimeService/ListContainers",
	}

	var lastErr error
	for _, method := range methods {
		var response []byte
		if err := conn.Invoke(ctx, method, []byte{}, &response); err != nil {
			lastErr = err
			continue
		}
		return parseCRIListContainersResponse(response), nil
	}
	return nil, lastErr
}

type rawProtoCodec struct{}

func (rawProtoCodec) Name() string {
	return "proto"
}

func (rawProtoCodec) Marshal(v any) ([]byte, error) {
	switch value := v.(type) {
	case []byte:
		return value, nil
	case *[]byte:
		return *value, nil
	default:
		return nil, fmt.Errorf("raw proto marshal: unsupported %T", v)
	}
}

func (rawProtoCodec) Unmarshal(data []byte, v any) error {
	switch value := v.(type) {
	case *[]byte:
		*value = append((*value)[:0], data...)
		return nil
	default:
		return fmt.Errorf("raw proto unmarshal: unsupported %T", v)
	}
}
