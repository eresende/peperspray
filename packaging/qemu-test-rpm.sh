#!/bin/sh
set -eu

usage() {
    cat <<'USAGE'
Usage:
  packaging/qemu-test-rpm.sh --image /path/to/fedora-cloud-base.qcow2 [--rpm target/rpm/RPMS/x86_64/peperspray-0.1.1-1.fc44.x86_64.rpm]

Environment overrides:
  QEMU_MEMORY       VM memory in MB. Default: 2048
  QEMU_CPUS         VM CPU count. Default: 2
  QEMU_SSH_PORT     Host SSH forwarding port. Default: 2223
  QEMU_ACCEL        VM accelerator: auto, kvm, or tcg. Default: auto
  QEMU_EXTRA_ARGS   Extra args passed to qemu-system-x86_64
USAGE
}

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
IMAGE=""
RPM=""
MEMORY="${QEMU_MEMORY:-2048}"
CPUS="${QEMU_CPUS:-2}"
SSH_PORT="${QEMU_SSH_PORT:-2223}"
QEMU_ACCEL="${QEMU_ACCEL:-auto}"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --image)
            IMAGE="${2:-}"
            shift 2
            ;;
        --rpm)
            RPM="${2:-}"
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

if [ -z "$RPM" ]; then
    RPM="$(find "$ROOT_DIR/target/rpm/RPMS" -type f -name 'peperspray-*.rpm' 2>/dev/null | head -n1 || true)"
fi

for tool in qemu-system-x86_64 qemu-img cloud-localds ssh scp ssh-keygen; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "missing required tool: $tool" >&2
        exit 1
    fi
done

if [ ! -f "$IMAGE" ]; then
    echo "image not found: $IMAGE" >&2
    exit 1
fi

if [ -z "$RPM" ] || [ ! -f "$RPM" ]; then
    echo "rpm not found; pass --rpm or run packaging/build-rpm.sh first" >&2
    exit 1
fi

IMAGE="$(cd "$(dirname "$IMAGE")" && pwd)/$(basename "$IMAGE")"
RPM="$(cd "$(dirname "$RPM")" && pwd)/$(basename "$RPM")"

WORK_DIR="$ROOT_DIR/target/qemu-rpm-test"
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
  - name: fedora
    groups: wheel
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $(cat "$SSH_KEY.pub")
ssh_pwauth: false
package_update: false
EOF

cat > "$META_DATA" <<EOF
instance-id: peperspray-rpm-test
local-hostname: peperspray-rpm-test
EOF

qemu-img create -f qcow2 -F qcow2 -b "$IMAGE" "$VM_DISK" >/dev/null
cloud-localds "$SEED_ISO" "$USER_DATA" "$META_DATA"

case "$QEMU_ACCEL" in
    auto)
        if [ -e /dev/kvm ]; then
            QEMU_ACCEL_ARGS="-enable-kvm"
        else
            QEMU_ACCEL_ARGS="-machine accel=tcg"
        fi
        ;;
    kvm)
        QEMU_ACCEL_ARGS="-enable-kvm"
        ;;
    tcg)
        QEMU_ACCEL_ARGS="-machine accel=tcg"
        ;;
    *)
        echo "invalid QEMU_ACCEL: $QEMU_ACCEL" >&2
        exit 2
        ;;
esac

qemu-system-x86_64 \
    $QEMU_ACCEL_ARGS \
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

SSH_BASE="ssh -i $SSH_KEY -p $SSH_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 fedora@127.0.0.1"
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

echo "copying package..."
$SCP_BASE "$RPM" fedora@127.0.0.1:/tmp/peperspray.rpm >/dev/null

echo "installing package..."
$SSH_BASE 'sudo dnf install -y /tmp/peperspray.rpm'

echo "checking installed files and service..."
$SSH_BASE '
set -eux
command -v peperspray
command -v pepersprayd
test -f /etc/peperspray/config.toml
test -f /etc/logrotate.d/peperspray
sudo test -f /var/log/peperspray/events.jsonl
test -f /usr/lib/systemd/system/pepersprayd.service
test "$(stat -c %U:%G /etc/peperspray/config.toml)" = "root:root"
test "$(stat -c %a /etc/peperspray/config.toml)" = "644"
test "$(stat -c %U:%G /etc/logrotate.d/peperspray)" = "root:root"
test "$(stat -c %a /etc/logrotate.d/peperspray)" = "644"
test "$(sudo stat -c %U:%G /var/log/peperspray)" = "root:root"
test "$(sudo stat -c %a /var/log/peperspray)" = "750"
test "$(sudo stat -c %U:%G /var/log/peperspray/events.jsonl)" = "root:root"
test "$(sudo stat -c %a /var/log/peperspray/events.jsonl)" = "640"
sudo logrotate --debug /etc/logrotate.d/peperspray >/dev/null
sudo systemctl daemon-reload
sudo systemctl start pepersprayd.service
systemctl is-active --quiet pepersprayd.service
peperspray service status >/dev/null
sudo systemctl stop pepersprayd.service
'

echo "checking reinstall permission repair..."
$SSH_BASE '
set -eux
sudo chmod 0755 /var/log/peperspray
sudo chmod 0644 /var/log/peperspray/events.jsonl
sudo rpm -Uvh --replacepkgs /tmp/peperspray.rpm
test "$(sudo stat -c %U:%G /var/log/peperspray)" = "root:root"
test "$(sudo stat -c %a /var/log/peperspray)" = "750"
test "$(sudo stat -c %U:%G /var/log/peperspray/events.jsonl)" = "root:root"
test "$(sudo stat -c %a /var/log/peperspray/events.jsonl)" = "640"
'

echo "checking remove behavior..."
$SSH_BASE '
set -eu
sudo dnf remove -y peperspray
test ! -e /usr/bin/peperspray
test ! -e /usr/bin/pepersprayd
test ! -e /usr/lib/systemd/system/pepersprayd.service
test ! -e /var/log/peperspray/events.jsonl
'

echo "QEMU RPM package smoke test passed."
