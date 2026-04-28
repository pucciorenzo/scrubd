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

See `hack/current-detections.md` for operator-style examples using these lab
resources, and `hack/future-detections.md` for planned scenarios not fully
implemented yet.

The lab creates:

- `vethscrubd0` and `vethscrubd1`, an orphan veth pair
- `scrubd-leak-ns`, a stale network namespace
- `/tmp/scrubd-leak/var/lib/docker/overlay2/scrubd-leak/merged`, a container-looking tmpfs mount
- `/tmp/scrubd-leak/containerd-shim-runc-v2`, a fake runtime helper process

Docker Desktop runs containers inside a Linux VM. Running this repository on
macOS will not expose the VM kernel resources to host inspection, so use a
Linux host for end-to-end leak detection tests.

On non-Linux hosts, `scrubd` skips host resource inspection and emits a
warning. This avoids presenting local desktop state as container-runtime leak
evidence.

Expected detector coverage from the lab:

- `orphaned_veth_interface`
- `stale_network_namespace`
- `abandoned_container_mount`
- `orphaned_runtime_process`

The lab does not create cgroup or overlay snapshot fixtures. Those are more
host-specific and easier to make unsafe by accident.

## Validated Linux Flow

This flow was validated on Ubuntu 24.04 with Linux `6.11.0-21-generic` and
Go `1.26.2`:

```bash
make build
sudo hack/leak-lab.sh create
sudo ./scrubd scan
sudo ./scrubd scan --json
sudo ./scrubd scan --runtime docker
sudo hack/leak-lab.sh cleanup
sudo ./scrubd scan --runtime docker
```

Equivalent Makefile flow:

```bash
make linux-validate
```

The Makefile flow was also validated on a Linux `x86_64` host after rebuilding
`./scrubd` as an ELF Linux binary.

If validation fails with imports like
`container-leak-detector/internal/... is not in std`, the Linux checkout still
has the old pre-rename command under `cmd/container-leak`. The current command
is `cmd/scrubd`; remove the stale directory or refresh the checkout before
running validation.

If `sudo ./scrubd scan` prints binary garbage or `Syntax error: newline
unexpected`, the `scrubd` file was built for another OS or architecture.
Rebuild it on the Linux host with `make build` before scanning.

Observed behavior:

- `scan` in `auto` mode reported Docker available, containerd CRI unavailable,
  and stayed conservative by reporting the stale named namespace and abandoned
  overlay-looking mount while skipping global veth orphan checks.
- `scan --runtime docker` detected the synthetic veth pair, stale named
  namespace, and abandoned overlay-looking mount.
- `cleanup <mount-leak-id> --dry-run` printed the expected `umount` command
  without executing it.
- `explain <netns-leak-id>` showed namespace inode evidence and the
  `ip netns delete` cleanup plan.
- Runtime systemd service cgroups such as `docker.service`,
  `docker.socket`, and `containerd.service` were not reported as stale cgroups.
- After `hack/leak-lab.sh cleanup`, `scan --runtime docker` reported
  `No leaks detected.`
