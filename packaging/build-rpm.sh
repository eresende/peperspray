#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
VERSION="${PEPERSPRAY_VERSION:-0.1.4}"
RELEASE="${PEPERSPRAY_RELEASE:-1}"
TARGET="${PEPERSPRAY_TARGET:-}"
RPM_TOPDIR="$ROOT_DIR/target/rpm"
SOURCES_DIR="$RPM_TOPDIR/SOURCES"
SPECS_DIR="$RPM_TOPDIR/SPECS"
RPM_PATH="$RPM_TOPDIR/RPMS"

if ! command -v rpmbuild >/dev/null 2>&1; then
    echo "missing required tool: rpmbuild" >&2
    exit 1
fi

if [ -n "$TARGET" ]; then
    cargo build --release --locked --target "$TARGET"
    CARGO_TARGET_DIR="$ROOT_DIR/target/$TARGET/release"
else
    cargo build --release --locked
    CARGO_TARGET_DIR="$ROOT_DIR/target/release"
fi

rm -rf "$RPM_TOPDIR"
install -d "$SOURCES_DIR" "$SPECS_DIR"

install -m 0755 "$CARGO_TARGET_DIR/peperspray" "$SOURCES_DIR/peperspray"
install -m 0755 "$CARGO_TARGET_DIR/pepersprayd" "$SOURCES_DIR/pepersprayd"
install -m 0644 "$ROOT_DIR/packaging/etc/peperspray/config.toml" "$SOURCES_DIR/config.toml"
install -m 0644 "$ROOT_DIR/packaging/rpm/peperspray.logrotate" "$SOURCES_DIR/peperspray.logrotate"
install -m 0644 "$ROOT_DIR/packaging/systemd/pepersprayd.service" "$SOURCES_DIR/pepersprayd.service"
install -m 0644 "$ROOT_DIR/LICENSE-MIT" "$SOURCES_DIR/LICENSE-MIT"
install -m 0644 "$ROOT_DIR/LICENSE-APACHE" "$SOURCES_DIR/LICENSE-APACHE"
install -m 0644 "$ROOT_DIR/packaging/rpm/peperspray.spec" "$SPECS_DIR/peperspray.spec"

rpmbuild \
    --define "_topdir $RPM_TOPDIR" \
    --define "peperspray_version $VERSION" \
    --define "peperspray_release $RELEASE" \
    -bb "$SPECS_DIR/peperspray.spec"

find "$RPM_PATH" -type f -name 'peperspray-*.rpm' -print
