#!/usr/bin/env sh
set -eu

NAME="${SCRUBD_LEAK_NAME:-scrubd-leak}"
VETH_A="${SCRUBD_VETH_A:-vethscrubd0}"
VETH_B="${SCRUBD_VETH_B:-vethscrubd1}"
NETNS="${SCRUBD_NETNS:-scrubd-leak-ns}"
LAB_DIR="${SCRUBD_LAB_DIR:-/tmp/$NAME}"
MOUNT_DIR="$LAB_DIR/var/lib/docker/overlay2/$NAME/merged"
SHIM_BIN="$LAB_DIR/containerd-shim-runc-v2"
SHIM_PID="$LAB_DIR/containerd-shim.pid"

usage() {
	cat <<EOF
Usage: $0 create|cleanup|status|commands

Creates synthetic Linux host leaks for scrubd tests:
  - orphan veth pair: $VETH_A <-> $VETH_B
  - stale network namespace: $NETNS
  - abandoned container-looking mount: $MOUNT_DIR
  - orphan runtime helper process: $SHIM_BIN

Environment overrides:
  SCRUBD_LEAK_NAME
  SCRUBD_VETH_A
  SCRUBD_VETH_B
  SCRUBD_NETNS
  SCRUBD_LAB_DIR
EOF
}

need_linux() {
	if [ "$(uname -s)" != "Linux" ]; then
		echo "error: leak lab requires Linux host" >&2
		exit 1
	fi
}

need_root() {
	if [ "$(id -u)" != "0" ]; then
		echo "error: leak lab requires root" >&2
		exit 1
	fi
}

need_ip() {
	if ! command -v ip >/dev/null 2>&1; then
		echo "error: iproute2 command 'ip' not found" >&2
		exit 1
	fi
}

need_mount() {
	if ! command -v mount >/dev/null 2>&1; then
		echo "error: command 'mount' not found" >&2
		exit 1
	fi
	if ! command -v umount >/dev/null 2>&1; then
		echo "error: command 'umount' not found" >&2
		exit 1
	fi
	if ! command -v mountpoint >/dev/null 2>&1; then
		echo "error: command 'mountpoint' not found" >&2
		exit 1
	fi
}

need_sleep() {
	if ! command -v sleep >/dev/null 2>&1; then
		echo "error: command 'sleep' not found" >&2
		exit 1
	fi
}

safe_lab_dir() {
	case "$LAB_DIR" in
	/tmp/*)
		;;
	*)
		echo "error: SCRUBD_LAB_DIR must be under /tmp" >&2
		exit 1
		;;
	esac
}

create() {
	need_linux
	need_root
	need_ip
	need_mount
	need_sleep
	safe_lab_dir

	if ! ip link show "$VETH_A" >/dev/null 2>&1 && ! ip link show "$VETH_B" >/dev/null 2>&1; then
		ip link add "$VETH_A" type veth peer name "$VETH_B"
		ip link set "$VETH_A" up
		ip link set "$VETH_B" up
	fi

	if ! ip netns list | awk '{print $1}' | grep -Fx "$NETNS" >/dev/null 2>&1; then
		ip netns add "$NETNS"
	fi

	mkdir -p "$MOUNT_DIR"
	if ! mountpoint -q "$MOUNT_DIR"; then
		mount -t tmpfs "$NAME" "$MOUNT_DIR"
	fi

	mkdir -p "$LAB_DIR"
	if [ ! -x "$SHIM_BIN" ]; then
		cp "$(command -v sleep)" "$SHIM_BIN"
		chmod 755 "$SHIM_BIN"
	fi
	if [ ! -s "$SHIM_PID" ] || ! kill -0 "$(cat "$SHIM_PID")" >/dev/null 2>&1; then
		"$SHIM_BIN" 3600 &
		echo "$!" >"$SHIM_PID"
	fi

	echo "$NAME created"
	echo "veth: $VETH_A $VETH_B"
	echo "netns: $NETNS"
	echo "mount: $MOUNT_DIR"
	echo "process pid: $(cat "$SHIM_PID")"
}

cleanup() {
	need_linux
	need_root
	need_ip
	need_mount
	safe_lab_dir

	if ip link show "$VETH_A" >/dev/null 2>&1; then
		ip link delete "$VETH_A"
	elif ip link show "$VETH_B" >/dev/null 2>&1; then
		ip link delete "$VETH_B"
	fi

	if ip netns list | awk '{print $1}' | grep -Fx "$NETNS" >/dev/null 2>&1; then
		ip netns delete "$NETNS"
	fi

	if [ -s "$SHIM_PID" ]; then
		pid="$(cat "$SHIM_PID")"
		if kill -0 "$pid" >/dev/null 2>&1; then
			kill -TERM "$pid" || true
		fi
		rm -f "$SHIM_PID"
	fi

	if mountpoint -q "$MOUNT_DIR"; then
		umount "$MOUNT_DIR"
	fi
	rm -rf "$LAB_DIR"

	echo "$NAME cleaned"
}

status() {
	need_linux
	need_ip
	need_mount

	ip link show "$VETH_A" 2>/dev/null || true
	ip link show "$VETH_B" 2>/dev/null || true
	ip netns list | awk '{print $1}' | grep -Fx "$NETNS" || true
	mountpoint "$MOUNT_DIR" 2>/dev/null || true
	if [ -s "$SHIM_PID" ]; then
		pid="$(cat "$SHIM_PID")"
		if kill -0 "$pid" >/dev/null 2>&1; then
			ps -p "$pid" -o pid= -o comm= -o args=
		fi
	fi
}

commands() {
	cat <<EOF
sudo $0 create
sudo $0 status
sudo $0 cleanup
EOF
}

case "${1:-}" in
create)
	create
	;;
cleanup)
	cleanup
	;;
status)
	status
	;;
commands)
	commands
	;;
-h|--help|help)
	usage
	;;
*)
	usage >&2
	exit 2
	;;
esac
