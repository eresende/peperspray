#!/bin/sh
set -eu

usage() {
    cat <<'USAGE'
Usage:
  packaging/build-rpm-container.sh

Environment overrides:
  CONTAINER_ENGINE  Container runtime. Default: docker
  RPM_BUILD_IMAGE   Fedora/RHEL-family image. Default: fedora:44

The script mounts the repository into a Fedora container, installs RPM build
tools there, and runs packaging/build-rpm.sh. Use QEMU, not this container, for
package lifecycle validation under systemd.
USAGE
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

if [ "$#" -gt 0 ]; then
    echo "unknown argument: $1" >&2
    usage >&2
    exit 2
fi

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
ENGINE="${CONTAINER_ENGINE:-docker}"
IMAGE="${RPM_BUILD_IMAGE:-fedora:44}"

if ! command -v "$ENGINE" >/dev/null 2>&1; then
    echo "missing required container engine: $ENGINE" >&2
    exit 1
fi

case "$ENGINE" in
    podman)
        VOLUME="$ROOT_DIR:/work:Z"
        ;;
    docker)
        if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" = "Enforcing" ]; then
            VOLUME="$ROOT_DIR:/work:Z"
        else
            VOLUME="$ROOT_DIR:/work"
        fi
        ;;
    *)
        VOLUME="$ROOT_DIR:/work"
        ;;
esac

"$ENGINE" run --rm \
    -v "$VOLUME" \
    -w /work \
    "$IMAGE" \
    sh -lc 'dnf install -y rpm-build systemd-rpm-macros rust cargo gcc make findutils && packaging/build-rpm.sh'
