# Scrubd

Scrubd is a Go CLI for finding leaked container-runtime resources on a Linux host. It inspects host state, collects Docker/containerd/Podman runtime inventory, correlates resources with running containers, and reports likely leftovers with evidence and cleanup guidance.

The tool is read-only by default. Cleanup actions are explicit, argv-based, dry-run capable, and require `--force` before destructive execution.

## Current Capabilities

- Inspect host resources:
  - network interfaces
  - named and process network namespaces
  - mountinfo entries
  - Docker and containerd overlay snapshots
  - cgroups
  - relevant processes
- Collect runtime inventory:
  - Docker containers and container PIDs from `/var/run/docker.sock`
  - containerd CRI containers from `/run/containerd/containerd.sock`
  - Podman containers and container PIDs from `/run/podman/podman.sock`
- Detect leak types:
  - orphaned veth interfaces
  - stale runtime-looking network bridges
  - stale named network namespaces
  - abandoned container mounts
  - dangling overlay snapshots
  - stale cgroups
  - orphaned runtime helper processes
- Report output:
  - text scan report
  - stable JSON scan report
  - per-leak explanation
- Scan filtering:
  - minimum severity filter for text and JSON output
- Cleanup:
  - dry-run cleanup plan output
  - guarded destructive execution with `--force`
  - shell-free command execution through argv arrays

## Usage

```bash
go run ./cmd/scrubd scan
go run ./cmd/scrubd scan --json
go run ./cmd/scrubd scan --runtime docker
go run ./cmd/scrubd scan --runtime containerd
go run ./cmd/scrubd scan --runtime podman
go run ./cmd/scrubd scan --min-severity high
go run ./cmd/scrubd explain <leak-id>
go run ./cmd/scrubd explain <leak-id> --runtime docker
go run ./cmd/scrubd cleanup <leak-id> --dry-run
go run ./cmd/scrubd cleanup <leak-id> --force
```

## Install From Source

Build a local binary:

```bash
make build
```

Install it somewhere on `PATH`:

```bash
sudo install -m 0755 scrubd /usr/local/bin/scrubd
```

Installed binary examples:

```bash
scrubd scan
scrubd scan --json
scrubd scan --min-severity medium
scrubd cleanup <leak-id> --dry-run
```

Makefile shortcuts:

```bash
make check
make build
make leak-create
make sudo-scan
make sudo-scan-json
make sudo-scan-docker
make leak-cleanup
```

On a disposable Linux host, this runs the validated leak-lab flow end to end:

```bash
make linux-validate
```

Supported runtime values:

- `auto`
- `docker`
- `containerd`
- `podman`

Supported minimum severity values:

- `low`
- `medium`
- `high`
- `critical`

## Real World Scenario

You notice a Linux server is unhealthy after a failed deploy: disk usage is
high, container networking is unreliable, and `ps` shows old runtime helper
processes. You do not want to run broad prune commands yet because the host may
still have valid stopped containers and images.

First, run a read-only scan:

```bash
scrubd scan --json
```

The report shows an abandoned overlay mount, a stale named network namespace,
and an orphaned runtime helper process. You inspect one finding before touching
the host:

```bash
scrubd explain <leak-id>
```

Then preview cleanup:

```bash
scrubd cleanup <leak-id> --dry-run
```

After confirming the evidence and command are correct, run the guarded cleanup:

```bash
scrubd cleanup <leak-id> --force
```

For a disposable Linux drill that creates today's supported leak shapes, use
[`hack/leak-lab.sh`](hack/leak-lab.sh) and the examples in
[`hack/current-detections.md`](hack/current-detections.md). Future production
ideas, such as CNI IPAM leaks, stale firewall rules, and volume drift, are
tracked in [`hack/future-detections.md`](hack/future-detections.md).

## Build And Test

```bash
go fmt ./...
go test ./...
go vet ./...
go build ./...
```

On systems where the default Go build cache is outside the writable workspace, use a local cache:

```bash
GOCACHE=/tmp/scrubd-go-build go test ./...
GOCACHE=/tmp/scrubd-go-build go vet ./...
GOCACHE=/tmp/scrubd-go-build go build ./...
```

## Release Artifacts

The command name and installed binary name are `scrubd`.

Build local Linux release directories:

```bash
make dist VERSION=0.1.0
```

Artifact layout:

```text
dist/
  scrubd_0.1.0_linux_amd64/
    scrubd
  scrubd_0.1.0_linux_arm64/
    scrubd
```

The binaries are built with `CGO_ENABLED=0`, `-trimpath`, and stripped linker
flags so they are suitable for copying to Linux hosts.

The container image uses the same `/scrubd` binary:

```bash
make docker-build IMAGE=scrubd:0.1.0
```

## Safety Model

- `scan` and `explain` are read-only.
- Runtime-correlated detections are skipped when no runtime inventory is
  available, because Docker/containerd/Podman socket or permission failures make
  orphan correlation unsafe.
- `cleanup <leak-id> --dry-run` prints commands without executing them.
- `cleanup <leak-id>` without `--force` prints a plan and clearly skips destructive steps.
- `cleanup <leak-id> --force` executes cleanup steps through `exec.Command`, not a shell.
- Stale bridge findings do not get direct cleanup commands because bridge ownership can come from runtime network metadata, CNI state, or host configuration.
- Dangling overlay snapshots currently do not get a direct `rm` cleanup plan because snapshot directories can back images or stopped containers. The report recommends runtime garbage collection or manual metadata review.

## Detection Rules

### Orphaned Veth Interfaces

Function: `detect.DetectOrphanVeth`

Flags veth interfaces only when every selected runtime inventory is available and no running runtime containers are known. This avoids claiming orphaned network devices while another selected runtime may be unreadable. The cleanup plan uses:

```bash
ip link delete <interface>
```

### Stale Network Namespaces

Function: `detect.DetectStaleNetworkNamespaces`

Flags named namespaces from `/var/run/netns` when the namespace inode is known and no process network namespace has the same inode. Namespaces with unreadable or unknown inode are skipped and surfaced by inspection warnings instead of reported as stale. The cleanup plan uses:

```bash
ip netns delete <namespace>
```

### Stale Network Bridges

Function: `detect.DetectStaleNetworkBridges`

Flags generated-looking runtime bridge names such as `br-*`, `cni*`, and `podman*` only when every selected runtime inventory is available, no running runtime containers are known, and the bridge has no attached bridge ports. Default bridges such as `docker0`, `cni0`, and `podman0` are skipped. No destructive cleanup command is generated because bridge ownership can come from runtime network metadata, CNI state, or host configuration.

### Abandoned Container Mounts

Function: `detect.DetectAbandonedMounts`

Flags Docker `overlay2/.../merged` and containerd `overlayfs/snapshots/.../fs` mounts when the mount point matches those path segments exactly and no known container ID appears in the mount fingerprint. Broad runtime directory mounts and suffix lookalikes such as `merged-backup` or `fs-old` are skipped to avoid unsafe cleanup suggestions. The cleanup plan uses:

```bash
umount <mount-point>
```

### Dangling Overlay Snapshots

Function: `detect.DetectDanglingOverlaySnapshots`

Flags recognized Docker/containerd overlay snapshot directories when their path matches runtime snapshot path segments, they are not mounted, and no known container ID appears in the snapshot path. Mount correlation uses path-boundary checks so sibling snapshot IDs such as `12` and `123` are not confused. Unknown snapshot runtimes are skipped. No destructive cleanup command is generated.

### Stale Cgroups

Function: `detect.DetectStaleCgroups`

Flags runtime-looking cgroup paths, such as container scopes, pod cgroups under `kubepods`, or `libpod`, when the cgroup process count is known to be zero and no known container ID appears in the path. Matching is segment-based so unrelated names containing strings like `docker` are skipped. Docker/containerd systemd service and socket units are also skipped. The cleanup plan uses:

```bash
rmdir /sys/fs/cgroup<path>
```

### Orphaned Runtime Processes

Function: `detect.DetectOrphanRuntimeProcesses`

Flags helper processes for selected available runtimes, such as `containerd-shim*`, `docker-proxy`, Podman `conmon`, and runtime-contextual `runc`, when their command line has no known container ID reference. Generic `runc` commands without Docker, containerd, Podman, or libpod context are skipped. This avoids Docker-only scans reporting helpers from other runtimes. The cleanup plan uses:

```bash
kill -TERM <pid>
```

## Architecture

```text
cmd/scrubd/
  main.go              CLI parsing, command routing, scan orchestration

internal/runtime/
  model.go             runtime inventory models and runtime names
  collector.go         runtime collector dispatch
  docker.go            Docker socket inventory and per-container inspect
  containerd.go        containerd CRI inventory
  podman.go            Podman socket inventory and per-container inspect
  cri_proto.go         minimal CRI protobuf response parser

internal/inspect/
  model.go             host inventory models and inspected paths
  inspect.go           host inventory orchestration
  network.go           network interface inspection
  namespace.go         network namespace inspection
  mounts.go            mountinfo parsing
  snapshots.go         Docker/containerd overlay snapshot inspection
  cgroups.go           cgroup parsing
  processes.go         process inspection

internal/detect/
  leaks.go             leak model, severity, stable IDs
  rules.go             leak detection rules

internal/report/
  model.go             report model and summary
  text.go              human-readable report writer
  json.go              JSON report writer
  explain.go           single-leak explanation writer

internal/cleanup/
  model.go             cleanup step model
  execute.go           dry-run, force guard, command execution
```

## Function Map

### CLI

- `main`: process entrypoint.
- `run`: dispatches `scan`, `explain`, `cleanup`, and help commands.
- `runScan`: parses scan flags, builds a report, writes text or JSON.
- `buildScanReport`: collects host/runtime inventory, runs detection, filters by minimum severity, builds report summary.
- `runExplain`: finds a leak in the current scan and writes explanation output.
- `runCleanup`: finds a leak in the current scan and executes or prints its cleanup plan.
- `parseLeakCommandArgs`: parses `<leak-id>` and `--runtime` for leak-specific commands.
- `parseCleanupArgs`: parses cleanup-specific flags.
- `filterCleanupFlags`: removes cleanup flags before shared leak-arg parsing.
- `findLeak`: finds a leak by stable ID.
- `validRuntime`: validates runtime selector.

### Runtime Inventory

- `runtime.NewCollector`: creates a runtime collector with explicit paths.
- `runtime.NewDefaultCollector`: creates a runtime collector with default socket paths.
- `runtime.ValidName`: validates `auto`, `docker`, `containerd`, or `podman`.
- `runtime.Collector.Inventories`: dispatches runtime collection by selected runtime.
- `runtime.Collector.Docker`: queries Docker `/containers/json?all=true` and per-container inspect over system or rootless Unix socket candidates.
- `runtime.Collector.Containerd`: queries containerd CRI `ListContainers` over system or rootless Unix socket candidates.
- `runtime.Collector.Podman`: queries Podman's Docker-compatible `/containers/json?all=true` API and per-container inspect over system or rootless Unix socket candidates.
- Runtime warnings distinguish missing sockets, permission problems, connect timeouts, and CRI API unavailability.

### Host Inspection

- `inspect.NewCollector`: creates a host collector with explicit paths.
- `inspect.NewDefaultCollector`: creates a host collector with default Linux paths.
- `inspect.Collector.Inventory`: collects all host inventory sections.
- `inspect.Collector.NetworkInterfaces`: lists interfaces and classifies interface kind.
- `inspect.Collector.NetworkNamespaces`: reads named and process network namespaces.
- `inspect.Collector.Mounts`: reads and parses `/proc/self/mountinfo`.
- `inspect.Collector.Snapshots`: reads Docker and containerd overlay snapshot directories.
- `inspect.Collector.Cgroups`: scans runtime-looking cgroup directories under `/sys/fs/cgroup`, falling back to `/proc/self/cgroup` when the cgroup root is unavailable.
- `inspect.Collector.Processes`: reads process command names and argv from `/proc`.

### Detection

- `detect.Detect`: runs every detection rule and sorts leaks by severity, type, and resource.
- `detect.DetectOrphanVeth`: finds orphaned veth interfaces.
- `detect.DetectStaleNetworkBridges`: finds runtime-looking bridges without attached ports or running containers.
- `detect.DetectStaleNetworkNamespaces`: finds named netns entries without process inode matches.
- `detect.DetectAbandonedMounts`: finds runtime mounts without known container references.
- `detect.DetectDanglingOverlaySnapshots`: finds unmounted overlay snapshots without known container references.
- `detect.DetectStaleCgroups`: finds runtime-looking cgroups without known container references.
- `detect.DetectOrphanRuntimeProcesses`: finds runtime helper processes without known container references.
- `detect.NewLeak`: creates a leak and assigns a stable ID.
- `detect.StableID`: creates deterministic leak IDs from leak type and resource.
- `detect.Leak.Validate`: checks required leak fields.
- `detect.ValidSeverity`: validates severity names.
- `detect.SeverityRank`: ranks severity for sorting and filtering.
- `detect.FilterByMinSeverity`: filters leaks by minimum severity.

### Reporting

- `report.New`: builds a report and summary from runtimes, leaks, and warnings.
- `report.WriteText`: writes the human-readable scan report.
- `report.WriteJSON`: writes indented JSON output.
- `report.WriteExplain`: writes detailed output for one leak.

### Cleanup

- `cleanup.Step.Validate`: validates cleanup step shape.
- `cleanup.Execute`: prints steps, honors dry-run/force guards, and executes allowed steps.
- `cleanup.ExecRunner.Run`: executes one command via `exec.Command`.
- `cleanup.FormatCommand`: formats argv commands for display.

## Data Models

```go
type Leak struct {
	ID          string
	Type        LeakType
	Severity    Severity
	Resource    string
	Reason      string
	Evidence    []string
	SafeAction  string
	RiskNotes   string
	CleanupPlan []cleanup.Step
}

type Step struct {
	Description string
	Command     []string
	Destructive bool
}

type Report struct {
	GeneratedAt time.Time
	Runtime     runtime.Name
	Runtimes    []runtime.Inventory
	Leaks       []detect.Leak
	Warnings    []string
	Summary     Summary
}
```

## Example Text Output

```text
Container leak scan report

generated: 2026-04-27T18:19:22Z
runtime: docker
runtimes: 1 available / 1 checked
containers: 0
leaks: 3 (critical=0 high=1 medium=2 low=0)

[HIGH] orphaned_veth_interface
  id: leak-d2ffeb6af46d
  resource: vethscrubd0
  reason: veth interface found but no running runtime container references are available
  suggested action: ip link delete vethscrubd0
  evidence: interface index: 13
  evidence: interface kind: veth
  evidence: runtime inventories: all selected runtimes available
  evidence: running containers: 0
  risk: delete only after confirming no workload uses this interface
  cleanup: available (1 step)
  next step: run `scrubd cleanup leak-d2ffeb6af46d --dry-run`, confirm the interface is not attached to a live workload, then rerun with `--force` only if the resource is safe to modify

[MEDIUM] abandoned_container_mount
  id: leak-d4e12caa565a
  resource: /tmp/scrubd-leak/var/lib/docker/overlay2/scrubd-leak/merged
  reason: container runtime mount has no matching known container reference
  suggested action: umount /tmp/scrubd-leak/var/lib/docker/overlay2/scrubd-leak/merged
  evidence: filesystem: tmpfs
  evidence: known container reference: none
  risk: unmount only after confirming no runtime task or process still uses this mount
  cleanup: available (1 step)
  next step: run `scrubd cleanup leak-d4e12caa565a --dry-run`, confirm no process or runtime task is using the mount, then rerun with `--force` only if the resource is safe to modify

[MEDIUM] stale_network_namespace
  id: leak-5c5479969eb4
  resource: /var/run/netns/scrubd-leak-ns
  reason: named network namespace has no matching process network namespace
  suggested action: ip netns delete scrubd-leak-ns
  evidence: namespace source: netns
  evidence: matching process namespace: none
  risk: delete only after confirming no CNI plugin or workload still owns this namespace
  cleanup: available (1 step)
  next step: run `scrubd cleanup leak-5c5479969eb4 --dry-run`, confirm no process, CNI plugin, or workload still owns the namespace, then rerun with `--force` only if the resource is safe to modify
```

## JSON Output

`scan --json` emits:

- `schema_version`
- `generated_at`
- `runtime`
- `runtimes`
- `leaks`
- `warnings`
- `summary`

This shape is intended for automation and tests. `schema_version` is currently
`scrubd.scan.v1`; automation should check it before parsing fields strictly.

`scan --min-severity <level>` filters `leaks` before summary counts are computed, so text and JSON totals match the displayed leak set.

Minimal JSON shape:

```json
{
  "schema_version": "scrubd.scan.v1",
  "runtime": "docker",
  "leaks": [
    {
      "id": "leak-d2ffeb6af46d",
      "type": "orphaned_veth_interface",
      "severity": "high",
      "resource": "vethscrubd0",
      "cleanup_plan": [
        {
          "description": "delete veth interface vethscrubd0",
          "command": ["ip", "link", "delete", "vethscrubd0"],
          "destructive": true
        }
      ]
    }
  ],
  "summary": {
    "leak_count": 1
  }
}
```

## Project Status

Implemented MVP:

- CLI shell
- runtime inventory layer
- read-only host inspection layer
- detection rules for all planned MVP leak types
- text/JSON/explain reporting
- dry-run and guarded cleanup execution
- unit tests for core parsing, detection, inspection, reporting, runtime, and cleanup behavior

Future work:

- richer containerd task and sandbox metadata
- Kubernetes-aware correlation
- CRI-O support
- Prometheus metrics exporter
- historical scan storage
- broader integration testing on Linux hosts
