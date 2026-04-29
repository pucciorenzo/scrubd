package detect

import (
	"fmt"
	"strconv"
	"strings"

	"scrubd/internal/cleanup"
	"scrubd/internal/inspect"
	runtimeinv "scrubd/internal/runtime"
)

func DetectOrphanRuntimeProcesses(input Input) []Leak {
	if !runtimeCorrelationAvailable(input.Runtimes) {
		return nil
	}

	runningIDs := runningContainerIDs(input.Runtimes)
	knownIDs := knownContainerIDs(input.Runtimes)

	var leaks []Leak
	for _, process := range input.Host.Processes {
		if !runtimeProcessCandidate(process, input.Runtimes) {
			continue
		}
		if referencesAnyContainer(processFingerprint(process), knownIDs) {
			continue
		}
		if referencesAnyRunningContainer(processFingerprint(process), runningIDs) {
			continue
		}

		resource := strconv.Itoa(process.PID)
		leak := NewLeak(
			LeakTypeRuntimeProcess,
			SeverityMedium,
			resource,
			"container runtime helper process has no matching known container reference",
		)
		leak.Evidence = []string{
			fmt.Sprintf("pid: %d", process.PID),
			fmt.Sprintf("command: %s", process.Command),
			fmt.Sprintf("args: %s", strings.Join(process.Args, " ")),
			"known container reference: none",
		}
		leak.SafeAction = fmt.Sprintf("kill -TERM %d", process.PID)
		leak.RiskNotes = "terminate only after confirming the runtime no longer owns this process"
		leak.CleanupPlan = []cleanup.Step{{
			Description: fmt.Sprintf("terminate runtime helper process %d", process.PID),
			Command:     []string{"kill", "-TERM", resource},
			Destructive: true,
		}}
		leaks = append(leaks, leak)
	}
	return leaks
}

func runtimeProcessCandidate(process inspect.Process, runtimes []runtimeinv.Inventory) bool {
	command := strings.ToLower(process.Command)
	for _, runtime := range runtimes {
		if !runtime.Available && len(runtime.Containers) == 0 {
			continue
		}
		switch runtime.Runtime {
		case runtimeinv.NameDocker:
			if strings.Contains(command, "docker-proxy") || dockerRuncProcess(process) {
				return true
			}
		case runtimeinv.NameContainerd:
			if strings.Contains(command, "containerd-shim") || containerdRuncProcess(process) {
				return true
			}
		case runtimeinv.NamePodman:
			if strings.Contains(command, "conmon") || podmanRuncProcess(process) {
				return true
			}
		}
	}
	return false
}

func processFingerprint(process inspect.Process) string {
	parts := append([]string{process.Command}, process.Args...)
	return strings.Join(parts, " ")
}

func dockerRuncProcess(process inspect.Process) bool {
	return runcProcessWithContext(process, "docker")
}

func containerdRuncProcess(process inspect.Process) bool {
	return runcProcessWithContext(process, "containerd")
}

func podmanRuncProcess(process inspect.Process) bool {
	return runcProcessWithContext(process, "podman") || runcProcessWithContext(process, "libpod")
}

func runcProcessWithContext(process inspect.Process, runtimeName string) bool {
	if strings.ToLower(process.Command) != "runc" {
		return false
	}
	fingerprint := strings.ToLower(processFingerprint(process))
	return strings.Contains(fingerprint, runtimeName)
}
