package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func socketStatWarning(runtimeName, path string, err error) string {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fmt.Sprintf("%s socket missing: %s", runtimeName, path)
	case errors.Is(err, os.ErrPermission):
		return fmt.Sprintf("%s socket permission denied: %s", runtimeName, path)
	default:
		return fmt.Sprintf("%s socket unavailable: %v", runtimeName, err)
	}
}

func socketsMissingWarning(runtimeName string, paths []string) string {
	return fmt.Sprintf("%s socket missing: checked %s", runtimeName, strings.Join(paths, ", "))
}

func socketConnectWarning(runtimeName, path string, err error) string {
	switch {
	case errors.Is(err, os.ErrPermission):
		return fmt.Sprintf("%s socket permission denied: %s", runtimeName, path)
	case errors.Is(err, context.DeadlineExceeded), isTimeout(err):
		return fmt.Sprintf("%s socket connect timeout: %s", runtimeName, path)
	default:
		return fmt.Sprintf("%s socket connect failed: %v", runtimeName, err)
	}
}

func dockerAPIWarning(path string, err error) string {
	switch {
	case errors.Is(err, os.ErrPermission):
		return fmt.Sprintf("docker socket permission denied: %s", path)
	case errors.Is(err, context.DeadlineExceeded), isTimeout(err):
		return fmt.Sprintf("docker API timeout: %s", path)
	default:
		return fmt.Sprintf("docker API unavailable: %v", err)
	}
}

func podmanAPIWarning(path string, err error) string {
	switch {
	case errors.Is(err, os.ErrPermission):
		return fmt.Sprintf("podman socket permission denied: %s", path)
	case errors.Is(err, context.DeadlineExceeded), isTimeout(err):
		return fmt.Sprintf("podman API timeout: %s", path)
	default:
		return fmt.Sprintf("podman API unavailable: %v", err)
	}
}

func criInventoryWarning(err error) string {
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.Unimplemented:
			return "containerd CRI API unavailable: runtime service not implemented"
		case codes.DeadlineExceeded:
			return "containerd CRI API timeout"
		}
	}
	if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		return "containerd CRI API timeout"
	}
	return fmt.Sprintf("containerd CRI inventory: %v", err)
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
