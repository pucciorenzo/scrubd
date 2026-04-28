package runtime

import (
	"context"
	"errors"
	"os"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestSocketStatWarning(t *testing.T) {
	if got := socketStatWarning("docker", "/var/run/docker.sock", os.ErrNotExist); got != "docker socket missing: /var/run/docker.sock" {
		t.Fatalf("warning = %q", got)
	}
	if got := socketStatWarning("docker", "/var/run/docker.sock", os.ErrPermission); got != "docker socket permission denied: /var/run/docker.sock" {
		t.Fatalf("warning = %q", got)
	}
	if got := socketsMissingWarning("docker", []string{"/var/run/docker.sock", "/run/user/501/docker.sock"}); got != "docker socket missing: checked /var/run/docker.sock, /run/user/501/docker.sock" {
		t.Fatalf("warning = %q", got)
	}
}

func TestSocketConnectWarning(t *testing.T) {
	if got := socketConnectWarning("containerd", "/run/containerd/containerd.sock", os.ErrPermission); got != "containerd socket permission denied: /run/containerd/containerd.sock" {
		t.Fatalf("warning = %q", got)
	}
	if got := socketConnectWarning("containerd", "/run/containerd/containerd.sock", context.DeadlineExceeded); got != "containerd socket connect timeout: /run/containerd/containerd.sock" {
		t.Fatalf("warning = %q", got)
	}
}

func TestDockerAPIWarning(t *testing.T) {
	if got := dockerAPIWarning("/var/run/docker.sock", os.ErrPermission); got != "docker socket permission denied: /var/run/docker.sock" {
		t.Fatalf("warning = %q", got)
	}
	if got := dockerAPIWarning("/var/run/docker.sock", context.DeadlineExceeded); got != "docker API timeout: /var/run/docker.sock" {
		t.Fatalf("warning = %q", got)
	}
}

func TestCRIInventoryWarning(t *testing.T) {
	if got := criInventoryWarning(status.Error(codes.Unimplemented, "missing")); got != "containerd CRI API unavailable: runtime service not implemented" {
		t.Fatalf("warning = %q", got)
	}
	if got := criInventoryWarning(context.DeadlineExceeded); got != "containerd CRI API timeout" {
		t.Fatalf("warning = %q", got)
	}
	if got := criInventoryWarning(errors.New("boom")); got != "containerd CRI inventory: boom" {
		t.Fatalf("warning = %q", got)
	}
}
