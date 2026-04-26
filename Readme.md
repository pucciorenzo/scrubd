# Scrubd

Scrubd is a Go CLI for finding leaked container-runtime resources on a Linux host. It inspects host state, collects Docker/containerd runtime inventory, correlates resources with running containers, and reports likely leftovers with evidence and cleanup guidance.

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
- Detect leak types:
  - orphaned veth interfaces
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
go run ./cmd/scrubd scan --min-severity high
go run ./cmd/scrubd explain <leak-id>
go run ./cmd/scrubd explain <leak-id> --runtime docker
go run ./cmd/scrubd cleanup <leak-id> --dry-run
go run ./cmd/scrubd cleanup <leak-id> --force
```

Installed binary examples:

```bash
scrubd scan
scrubd scan --json
scrubd scan --min-severity medium
scrubd cleanup <leak-id> --dry-run
```

Supported runtime values:

- `auto`
- `docker`
- `containerd`

Supported minimum severity values:

- `low`
- `medium`
- `high`
- `critical`

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

## Safety Model

- `scan` and `explain` are read-only.
- `cleanup <leak-id> --dry-run` prints commands without executing them.
- `cleanup <leak-id>` without `--force` skips destructive steps.
- `cleanup <leak-id> --force` executes cleanup steps through `exec.Command`, not a shell.
- Dangling overlay snapshots currently do not get a direct `rm` cleanup plan because snapshot directories can back images or stopped containers. The report recommends runtime garbage collection or manual metadata review.

## Detection Rules

### Orphaned Veth Interfaces

Function: `detect.DetectOrphanVeth`

Flags veth interfaces when no running runtime containers are known. The cleanup plan uses:

```bash
ip link delete <interface>
```

### Stale Network Namespaces

Function: `detect.DetectStaleNetworkNamespaces`

Flags named namespaces from `/var/run/netns` when no process network namespace has the same inode. The cleanup plan uses:

```bash
ip netns delete <namespace>
```

### Abandoned Container Mounts

Function: `detect.DetectAbandonedMounts`

Flags runtime-looking mounts, such as Docker/containerd overlay mounts, when no running container ID appears in the mount fingerprint. The cleanup plan uses:

```bash
umount <mount-point>
```

### Dangling Overlay Snapshots

Function: `detect.DetectDanglingOverlaySnapshots`

Flags Docker/containerd overlay snapshot directories when they are not mounted and no running container ID appears in the snapshot path. No destructive cleanup command is generated.

### Stale Cgroups

Function: `detect.DetectStaleCgroups`

Flags runtime-looking cgroup paths, such as `docker`, `containerd`, `kubepods`, or `libpod`, when no running container ID appears in the path. The cleanup plan uses:

```bash
rmdir /sys/fs/cgroup<path>
```

### Orphaned Runtime Processes

Function: `detect.DetectOrphanRuntimeProcesses`

Flags helper processes such as `containerd-shim*`, `docker-proxy`, and `runc` when their command line has no running container ID reference. The cleanup plan uses:

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
- `runtime.ValidName`: validates `auto`, `docker`, or `containerd`.
- `runtime.Collector.Inventories`: dispatches runtime collection by selected runtime.
- `runtime.Collector.Docker`: queries Docker `/containers/json?all=false` and per-container inspect over the Unix socket.
- `runtime.Collector.Containerd`: queries containerd CRI `ListContainers` over gRPC.

### Host Inspection

- `inspect.NewCollector`: creates a host collector with explicit paths.
- `inspect.NewDefaultCollector`: creates a host collector with default Linux paths.
- `inspect.Collector.Inventory`: collects all host inventory sections.
- `inspect.Collector.NetworkInterfaces`: lists interfaces and classifies interface kind.
- `inspect.Collector.NetworkNamespaces`: reads named and process network namespaces.
- `inspect.Collector.Mounts`: reads and parses `/proc/self/mountinfo`.
- `inspect.Collector.Snapshots`: reads Docker and containerd overlay snapshot directories.
- `inspect.Collector.Cgroups`: reads and parses `/proc/self/cgroup`.
- `inspect.Collector.Processes`: reads process command names and argv from `/proc`.

### Detection

- `detect.Detect`: runs every detection rule and sorts leaks by severity, type, and resource.
- `detect.DetectOrphanVeth`: finds orphaned veth interfaces.
- `detect.DetectStaleNetworkNamespaces`: finds named netns entries without process inode matches.
- `detect.DetectAbandonedMounts`: finds runtime mounts without running container references.
- `detect.DetectDanglingOverlaySnapshots`: finds unmounted overlay snapshots without running container references.
- `detect.DetectStaleCgroups`: finds runtime-looking cgroups without running container references.
- `detect.DetectOrphanRuntimeProcesses`: finds runtime helper processes without running container references.
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

generated: 2026-04-25T21:18:35Z
runtime: auto
runtimes: 0 available / 2 checked
containers: 0
leaks: 1 (critical=0 high=1 medium=0 low=0)

[HIGH] orphaned_veth_interface
  id: leak-f03aba9c2c00
  resource: veth9f31a2
  reason: veth interface found but no running runtime container references are available
  suggested action: ip link delete veth9f31a2
  evidence: interface kind: veth
  risk: delete only after confirming no workload uses this interface
```

## JSON Output

`scan --json` emits:

- `generated_at`
- `runtime`
- `runtimes`
- `leaks`
- `warnings`
- `summary`

This shape is intended for automation and tests.

`scan --min-severity <level>` filters `leaks` before summary counts are computed, so text and JSON totals match the displayed leak set.

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
