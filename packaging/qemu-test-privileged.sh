#!/bin/sh
set -eu

usage() {
    cat <<'USAGE'
Usage:
  packaging/qemu-test-privileged.sh --image /path/to/ubuntu-24.04-server-cloudimg-amd64.img

Environment overrides:
  QEMU_MEMORY       VM memory in MB. Default: 2048
  QEMU_CPUS         VM CPU count. Default: 2
  QEMU_SSH_PORT     Host SSH forwarding port. Default: 2222
  QEMU_EXTRA_ARGS   Extra args passed to qemu-system-x86_64
USAGE
}

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
IMAGE=""
MEMORY="${QEMU_MEMORY:-2048}"
CPUS="${QEMU_CPUS:-2}"
SSH_PORT="${QEMU_SSH_PORT:-2222}"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --image)
            IMAGE="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [ -z "$IMAGE" ]; then
    echo "--image is required" >&2
    usage >&2
    exit 2
fi

for tool in qemu-system-x86_64 qemu-img cloud-localds ssh scp ssh-keygen cargo find; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "missing required tool: $tool" >&2
        exit 1
    fi
done

if [ ! -f "$IMAGE" ]; then
    echo "image not found: $IMAGE" >&2
    exit 1
fi

IMAGE="$(cd "$(dirname "$IMAGE")" && pwd)/$(basename "$IMAGE")"

echo "building privileged test artifacts..."
cargo build --bin pepersprayd
cargo test --test privileged_fanotify --no-run
cargo test --test privileged_path_identity --no-run

DAEMON="$ROOT_DIR/target/debug/pepersprayd"
FANOTIFY_TEST="$(find "$ROOT_DIR/target/debug/deps" -maxdepth 1 -type f -executable -name 'privileged_fanotify-*' | sort | tail -n 1)"
PATH_IDENTITY_TEST="$(find "$ROOT_DIR/target/debug/deps" -maxdepth 1 -type f -executable -name 'privileged_path_identity-*' | sort | tail -n 1)"

if [ ! -x "$DAEMON" ]; then
    echo "daemon binary not found: $DAEMON" >&2
    exit 1
fi

if [ -z "$FANOTIFY_TEST" ] || [ ! -x "$FANOTIFY_TEST" ]; then
    echo "privileged_fanotify test binary not found" >&2
    exit 1
fi

if [ -z "$PATH_IDENTITY_TEST" ] || [ ! -x "$PATH_IDENTITY_TEST" ]; then
    echo "privileged_path_identity test binary not found" >&2
    exit 1
fi

WORK_DIR="$ROOT_DIR/target/qemu-privileged-test"
VM_DISK="$WORK_DIR/disk.qcow2"
SEED_ISO="$WORK_DIR/seed.iso"
SSH_KEY="$WORK_DIR/id_ed25519"
USER_DATA="$WORK_DIR/user-data"
META_DATA="$WORK_DIR/meta-data"

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"

ssh-keygen -q -t ed25519 -N "" -f "$SSH_KEY"

cat > "$USER_DATA" <<EOF
#cloud-config
users:
  - name: ubuntu
    groups: sudo
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $(cat "$SSH_KEY.pub")
ssh_pwauth: false
package_update: false
EOF

cat > "$META_DATA" <<EOF
instance-id: peperspray-privileged-test
local-hostname: peperspray-privileged-test
EOF

qemu-img create -f qcow2 -F qcow2 -b "$IMAGE" "$VM_DISK" >/dev/null
cloud-localds "$SEED_ISO" "$USER_DATA" "$META_DATA"

qemu-system-x86_64 \
    -enable-kvm \
    -m "$MEMORY" \
    -smp "$CPUS" \
    -drive "file=$VM_DISK,if=virtio,format=qcow2" \
    -drive "file=$SEED_ISO,if=virtio,format=raw,readonly=on" \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22" \
    -device virtio-net-pci,netdev=net0 \
    -nographic \
    ${QEMU_EXTRA_ARGS:-} &

QEMU_PID=$!
cleanup() {
    kill "$QEMU_PID" >/dev/null 2>&1 || true
    wait "$QEMU_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

SSH_BASE="ssh -i $SSH_KEY -p $SSH_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 ubuntu@127.0.0.1"
SCP_BASE="scp -i $SSH_KEY -P $SSH_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

echo "waiting for VM SSH on localhost:$SSH_PORT..."
deadline=$(( $(date +%s) + 180 ))
while ! $SSH_BASE true >/dev/null 2>&1; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
        echo "timed out waiting for SSH" >&2
        exit 1
    fi
    sleep 2
done

echo "copying privileged test artifacts..."
$SSH_BASE 'mkdir -p /tmp/peperspray-privileged-tests'
$SCP_BASE \
    "$DAEMON" \
    "$FANOTIFY_TEST" \
    "$PATH_IDENTITY_TEST" \
    ubuntu@127.0.0.1:/tmp/peperspray-privileged-tests/ >/dev/null

echo "running privileged fanotify tests..."
$SSH_BASE '
set -eu
cd /tmp/peperspray-privileged-tests
chmod +x ./pepersprayd ./privileged_fanotify-* ./privileged_path_identity-*
test_bin="$(find . -maxdepth 1 -type f -executable -name "privileged_fanotify-*" | sort | tail -n 1)"
sudo env PEPERSPRAYD_BIN=/tmp/peperspray-privileged-tests/pepersprayd "$test_bin" --ignored --nocapture
'

echo "running privileged path-identity tests..."
$SSH_BASE '
set -eu
cd /tmp/peperspray-privileged-tests
test_bin="$(find . -maxdepth 1 -type f -executable -name "privileged_path_identity-*" | sort | tail -n 1)"
sudo env PEPERSPRAYD_BIN=/tmp/peperspray-privileged-tests/pepersprayd "$test_bin" --ignored --nocapture
'

echo "QEMU privileged integration tests passed."
