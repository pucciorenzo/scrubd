# Current Detection Examples

These examples describe what `scrubd` can detect today. Use them as operator
drills and as acceptance examples when validating changes.

Run the synthetic leak lab on a disposable Linux host or VM:

```bash
sudo hack/leak-lab.sh create
go run ./cmd/scrubd scan
go run ./cmd/scrubd scan --json
sudo hack/leak-lab.sh cleanup
```

Do not run the lab on a production host. It creates real network interfaces,
network namespaces, a mount, and a long-running process.

After cleanup, the Docker-scoped scan should return clean:

```bash
sudo ./scrubd scan --runtime docker
```

Expected result:

```text
leaks: 0 (critical=0 high=0 medium=0 low=0)

No leaks detected.
```

## Scenario 1: Network Looks Wrong After Container Churn

Symptom: the host has unexpected veth interfaces after several failed deploys.

Example investigation:

```bash
go run ./cmd/scrubd scan --min-severity high
```

Expected finding when runtime inventory is complete and no running containers
are known:

```text
[HIGH] orphaned_veth_interface
  resource: vethscrubd0
  reason: veth interface found but no running runtime container references are available
  suggested action: ip link delete vethscrubd0
```

Review before cleanup:

```bash
go run ./cmd/scrubd explain <leak-id>
go run ./cmd/scrubd cleanup <leak-id> --dry-run
```

Execute only after confirming the veth is not used by a workload:

```bash
go run ./cmd/scrubd cleanup <leak-id> --force
```

## Scenario 2: Stale Network Namespace

Symptom: `ip netns list` shows namespaces that no process appears to use.

Example investigation:

```bash
go run ./cmd/scrubd scan
```

Expected finding:

```text
[MEDIUM] stale_network_namespace
  resource: /var/run/netns/scrubd-leak-ns
  reason: named network namespace has no matching process network namespace
  suggested action: ip netns delete scrubd-leak-ns
```

Cleanup flow:

```bash
go run ./cmd/scrubd explain <leak-id>
go run ./cmd/scrubd cleanup <leak-id> --dry-run
go run ./cmd/scrubd cleanup <leak-id> --force
```

Validated dry-run shape:

```text
cleanup <leak-id>
mode: dry-run

- delete network namespace scrubd-leak-ns
  command: ip netns delete scrubd-leak-ns
  status: dry-run
```

## Scenario 3: Abandoned Overlay Mount

Symptom: deploys fail because runtime paths stay mounted after containers exit.

Example investigation:

```bash
go run ./cmd/scrubd scan --json
```

Expected finding:

```json
{
  "type": "abandoned_container_mount",
  "severity": "medium",
  "safe_action": "umount /tmp/scrubd-leak/var/lib/docker/overlay2/scrubd-leak/merged"
}
```

Cleanup flow:

```bash
go run ./cmd/scrubd explain <leak-id>
go run ./cmd/scrubd cleanup <leak-id> --dry-run
go run ./cmd/scrubd cleanup <leak-id> --force
```

## Scenario 4: Orphaned Runtime Helper Process

Symptom: `containerd-shim`, `docker-proxy`, or `runc`-like helpers remain after
the owning container is gone.

Example investigation:

```bash
go run ./cmd/scrubd scan --min-severity medium
```

Expected finding:

```text
[MEDIUM] orphaned_runtime_process
  reason: container runtime helper process has no matching known container reference
  suggested action: kill -TERM <pid>
```

Cleanup flow:

```bash
go run ./cmd/scrubd explain <leak-id>
go run ./cmd/scrubd cleanup <leak-id> --dry-run
go run ./cmd/scrubd cleanup <leak-id> --force
```

## Scenario 5: Dangling Overlay Snapshot

Symptom: disk usage grows under Docker or containerd overlay snapshot
directories.

Example investigation:

```bash
go run ./cmd/scrubd scan --min-severity low
```

Expected finding:

```text
[LOW] dangling_overlay_snapshot
  reason: overlay snapshot is not mounted and has no matching known container reference
  suggested action: docker runtime garbage collection or manual snapshot review
```

There is no direct `rm` cleanup plan for this leak type. Snapshot directories
can back images or stopped containers, so review runtime metadata first.

## Scenario 6: Stale Cgroup

Symptom: runtime-looking cgroups remain after workloads are gone.

Example investigation:

```bash
go run ./cmd/scrubd scan --min-severity low
```

Expected finding:

```text
[LOW] stale_cgroup
  reason: container runtime cgroup has no matching known container reference
  suggested action: rmdir /sys/fs/cgroup<path>
```

`scrubd` only reports this when the scanned cgroup has a known process count of
zero. Run `cleanup --dry-run` first and confirm ownership before using `--force`.
