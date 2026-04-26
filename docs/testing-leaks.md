# Testing Leaks

Real leaked containers are hard to create reliably without corrupting runtime
state or crashing Docker/containerd. For detector development, prefer synthetic
host resources with known names.

Use the leak lab on a disposable Linux host or VM:

```bash
sudo hack/leak-lab.sh create
sudo hack/leak-lab.sh status
sudo hack/leak-lab.sh cleanup
```

The lab creates:

- `vethscrubd0` and `vethscrubd1`, an orphan veth pair
- `scrubd-leak-ns`, a stale network namespace
- `/tmp/scrubd-leak/var/lib/docker/overlay2/scrubd-leak/merged`, a container-looking tmpfs mount
- `/tmp/scrubd-leak/containerd-shim-runc-v2`, a fake runtime helper process

Docker Desktop runs containers inside a Linux VM. Running this repository on
macOS will not expose the VM kernel resources to host inspection, so use a
Linux host for end-to-end leak detection tests.

Expected detector coverage from the lab:

- `orphaned_veth_interface`
- `stale_network_namespace`
- `abandoned_container_mount`
- `orphaned_runtime_process`

The lab does not create cgroup or overlay snapshot fixtures. Those are more
host-specific and easier to make unsafe by accident.
