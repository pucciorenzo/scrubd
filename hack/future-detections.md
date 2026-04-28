# Future Detection Examples

These scenarios are not fully implemented yet. Keep them as product examples
for future production-grade detector work.

## Future Scenario 1: Leftover Runtime Networks

Symptom: new containers cannot attach to networks, or host routing tables show
unexpected container bridges after failed deploys.

Potential future command:

```bash
scrubd scan --include-networks
```

Potential future finding:

```text
[MEDIUM] stale_runtime_network
  resource: br-deadbeef
  reason: runtime bridge has no runtime network metadata and no attached endpoints
  suggested action: docker network prune or targeted bridge cleanup after review
```

Production requirements:

- Correlate bridges with Docker/containerd/CNI metadata.
- Avoid deleting bridges with attached interfaces.
- Explain route, bridge, and endpoint evidence.

## Future Scenario 2: Leaked CNI IPAM State

Symptom: pods fail because the CNI plugin reports exhausted IP addresses even
though few workloads are running.

Potential future command:

```bash
scrubd scan --include-cni
```

Potential future finding:

```text
[HIGH] stale_cni_ipam_allocation
  resource: 10.244.2.41
  reason: CNI IP allocation has no matching sandbox, netns, or runtime container
  suggested action: remove CNI allocation after backing up plugin state
```

Production requirements:

- Support plugin-specific state formats.
- Treat CNI state as read-only until cleanup safety is proven.
- Include sandbox ID, netns, and allocation-file evidence.

## Future Scenario 3: Unreferenced Docker Volumes

Symptom: disk pressure comes from `/var/lib/docker/volumes`, but operators are
not sure which volumes are safe to remove.

Potential future command:

```bash
scrubd scan --include-volumes
```

Potential future finding:

```text
[LOW] unreferenced_runtime_volume
  resource: myapp_cache_old
  reason: volume has no container references and has not changed recently
  suggested action: docker volume rm myapp_cache_old after backup review
```

Production requirements:

- Distinguish anonymous, named, and externally managed volumes.
- Respect recent writes and labels.
- Keep cleanup disabled by default for ambiguous data.

## Future Scenario 4: Stale Port Forwarding Rules

Symptom: host ports appear busy after containers are gone.

Potential future command:

```bash
scrubd scan --include-firewall
```

Potential future finding:

```text
[MEDIUM] stale_runtime_port_rule
  resource: tcp/8080
  reason: firewall/NAT rule references no known container or runtime proxy
  suggested action: remove specific nftables/iptables rule after review
```

Production requirements:

- Support nftables and iptables.
- Match rules to runtime metadata and live listeners.
- Avoid broad firewall mutation; cleanup must be precise and auditable.

## Future Scenario 5: Runtime Metadata Drift

Symptom: runtime reports containers that no longer have corresponding process,
mount, cgroup, or namespace state.

Potential future command:

```bash
scrubd scan --runtime auto --include-metadata-drift
```

Potential future finding:

```text
[MEDIUM] stale_runtime_metadata
  resource: container <id>
  reason: runtime metadata exists but no process, cgroup, mount, or namespace state remains
  suggested action: runtime metadata repair or runtime garbage collection
```

Production requirements:

- Correlate all host inventory sections against stopped and running containers.
- Prefer runtime-supported cleanup commands.
- Avoid direct edits to runtime metadata stores.
