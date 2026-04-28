package runtime

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
)

func TestContainerdInventory(t *testing.T) {
	socketPath := tempSocketPath(t, "containerd.sock")
	server := newRawGRPCServer(t, socketPath, buildCRIListContainersResponse(
		buildCRIContainer("abc123", "web", "nginx:latest", 1),
	))
	defer server.Stop()

	inv := NewCollector(Paths{ContainerdSocket: socketPath}).Containerd()
	if !inv.Available {
		t.Fatalf("containerd inventory unavailable: %#v", inv.Warnings)
	}
	if len(inv.Warnings) != 0 {
		t.Fatalf("warnings = %#v", inv.Warnings)
	}
	if len(inv.Containers) != 1 {
		t.Fatalf("len(containers) = %d, want 1", len(inv.Containers))
	}

	container := inv.Containers[0]
	if container.ID != "abc123" || container.Names[0] != "web" || container.Image != "nginx:latest" || container.State != "running" {
		t.Fatalf("unexpected container: %#v", container)
	}
}

func TestContainerdInventoryReachableSocketWithoutCRI(t *testing.T) {
	socketPath := tempSocketPath(t, "containerd.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	defer listener.Close()

	done := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
		close(done)
	}()

	inv := NewCollector(Paths{ContainerdSocket: socketPath}).Containerd()
	if inv.Available {
		t.Fatalf("containerd inventory available without CRI: %#v", inv)
	}
	if len(inv.Warnings) != 1 {
		t.Fatalf("warnings = %#v", inv.Warnings)
	}
	<-done
}

func TestContainerdInventoryFallsBackToRootlessSocket(t *testing.T) {
	socketPath := tempSocketPath(t, "containerd.sock")
	server := newRawGRPCServer(t, socketPath, buildCRIListContainersResponse(
		buildCRIContainer("abc123", "web", "nginx:latest", 1),
	))
	defer server.Stop()

	inv := NewCollector(Paths{
		ContainerdSocket:  tempSocketPath(t, "missing.sock"),
		ContainerdSockets: []string{socketPath},
	}).Containerd()
	if !inv.Available {
		t.Fatalf("containerd inventory unavailable: %#v", inv.Warnings)
	}
	if len(inv.Warnings) != 0 {
		t.Fatalf("warnings = %#v, want none after fallback succeeds", inv.Warnings)
	}
	if len(inv.Containers) != 1 || inv.Containers[0].ID != "abc123" {
		t.Fatalf("containers = %#v, want fallback inventory", inv.Containers)
	}
}

func TestContainerdInventoryMissingSocket(t *testing.T) {
	inv := NewCollector(Paths{ContainerdSocket: tempSocketPath(t, "missing.sock")}).Containerd()
	if inv.Available {
		t.Fatal("containerd inventory available for missing socket")
	}
	if len(inv.Warnings) != 1 {
		t.Fatalf("warnings = %#v", inv.Warnings)
	}
	if !contains(inv.Warnings[0], "containerd socket missing: checked") {
		t.Fatalf("warning = %q, want checked socket warning", inv.Warnings[0])
	}
}

func TestParseCRIListContainersResponse(t *testing.T) {
	response := buildCRIListContainersResponse(
		buildCRIContainer("abc123", "web", "nginx:latest", 1),
		buildCRIContainer("def456", "job", "busybox:latest", 2),
	)

	containers, err := parseCRIListContainersResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if len(containers) != 2 {
		t.Fatalf("len(containers) = %d, want 2", len(containers))
	}
	if containers[0].State != "running" || containers[1].State != "exited" {
		t.Fatalf("unexpected states: %#v", containers)
	}
}

func TestParseCRIListContainersResponseRejectsMalformedData(t *testing.T) {
	_, err := parseCRIListContainersResponse([]byte{0x0a, 0xff})
	if err == nil {
		t.Fatal("expected malformed CRI response error")
	}
}

func TestContainerdInventoryWarnsOnMalformedCRIResponse(t *testing.T) {
	socketPath := tempSocketPath(t, "containerd.sock")
	server := newRawGRPCServer(t, socketPath, []byte{0x0a, 0xff})
	defer server.Stop()

	inv := NewCollector(Paths{ContainerdSocket: socketPath}).Containerd()
	if inv.Available {
		t.Fatalf("containerd inventory available with malformed CRI response: %#v", inv)
	}
	if len(inv.Containers) != 0 {
		t.Fatalf("containers = %#v, want none", inv.Containers)
	}
	if len(inv.Warnings) != 1 || !contains(inv.Warnings[0], "malformed CRI list containers response") {
		t.Fatalf("warnings = %#v, want malformed CRI warning", inv.Warnings)
	}
}

func newRawGRPCServer(t *testing.T, socketPath string, response []byte) *grpc.Server {
	t.Helper()

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})

	server := grpc.NewServer(grpc.ForceServerCodec(rawProtoCodec{}))
	service := &grpc.ServiceDesc{
		ServiceName: "runtime.v1.RuntimeService",
		HandlerType: (*rawRuntimeService)(nil),
		Methods: []grpc.MethodDesc{{
			MethodName: "ListContainers",
			Handler: func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
				var request []byte
				if err := dec(&request); err != nil {
					return nil, err
				}
				if interceptor == nil {
					return response, nil
				}
				info := &grpc.UnaryServerInfo{
					Server:     srv,
					FullMethod: "/runtime.v1.RuntimeService/ListContainers",
				}
				handler := func(context.Context, any) (any, error) {
					return response, nil
				}
				return interceptor(ctx, request, info, handler)
			},
		}},
	}
	server.RegisterService(service, rawRuntimeServiceImpl{})

	go func() {
		if err := server.Serve(listener); err != nil {
			t.Errorf("containerd test server: %v", err)
		}
	}()
	return server
}

type rawRuntimeService interface {
	rawRuntimeService()
}

type rawRuntimeServiceImpl struct{}

func (rawRuntimeServiceImpl) rawRuntimeService() {}

func buildCRIListContainersResponse(containers ...[]byte) []byte {
	var out []byte
	for _, container := range containers {
		out = appendProtoBytes(out, 1, container)
	}
	return out
}

func buildCRIContainer(id, name, image string, state uint64) []byte {
	var out []byte
	out = appendProtoString(out, 1, id)
	out = appendProtoBytes(out, 3, appendProtoString(nil, 1, name))
	out = appendProtoBytes(out, 4, appendProtoString(nil, 1, image))
	out = appendProtoVarintField(out, 6, state)
	return out
}

func appendProtoString(out []byte, field uint64, value string) []byte {
	return appendProtoBytes(out, field, []byte(value))
}

func appendProtoBytes(out []byte, field uint64, value []byte) []byte {
	out = appendProtoVarint(out, field<<3|2)
	out = appendProtoVarint(out, uint64(len(value)))
	return append(out, value...)
}

func appendProtoVarintField(out []byte, field uint64, value uint64) []byte {
	out = appendProtoVarint(out, field<<3)
	return appendProtoVarint(out, value)
}

func appendProtoVarint(out []byte, value uint64) []byte {
	for value >= 0x80 {
		out = append(out, byte(value)|0x80)
		value >>= 7
	}
	return append(out, byte(value))
}
