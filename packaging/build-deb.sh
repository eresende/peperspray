#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
PACKAGE_DIR="$ROOT_DIR/target/debian/package"
CONTROL_DIR="$PACKAGE_DIR/DEBIAN"
VERSION="${PEPERSPRAY_VERSION:-0.1.0}"
ARCH="${PEPERSPRAY_ARCH:-amd64}"
DEB_PATH="$ROOT_DIR/target/debian/peperspray_${VERSION}_${ARCH}.deb"

cargo build --release --locked

rm -rf "$PACKAGE_DIR"
install -d "$CONTROL_DIR"
install -d "$PACKAGE_DIR/usr/bin"
install -d "$PACKAGE_DIR/etc/peperspray"
install -d "$PACKAGE_DIR/etc/logrotate.d"
install -d -m 0750 "$PACKAGE_DIR/var/log/peperspray"
install -d "$PACKAGE_DIR/usr/lib/systemd/system"

install -m 0755 "$ROOT_DIR/target/release/peperspray" "$PACKAGE_DIR/usr/bin/peperspray"
install -m 0755 "$ROOT_DIR/target/release/pepersprayd" "$PACKAGE_DIR/usr/bin/pepersprayd"
install -m 0644 "$ROOT_DIR/packaging/etc/peperspray/config.toml" "$PACKAGE_DIR/etc/peperspray/config.toml"
install -m 0644 "$ROOT_DIR/packaging/logrotate/peperspray" "$PACKAGE_DIR/etc/logrotate.d/peperspray"
install -m 0640 /dev/null "$PACKAGE_DIR/var/log/peperspray/events.jsonl"
install -m 0644 "$ROOT_DIR/packaging/systemd/pepersprayd.service" "$PACKAGE_DIR/usr/lib/systemd/system/pepersprayd.service"

install -m 0644 "$ROOT_DIR/packaging/deb/control" "$CONTROL_DIR/control"
install -m 0644 "$ROOT_DIR/packaging/deb/conffiles" "$CONTROL_DIR/conffiles"
install -m 0755 "$ROOT_DIR/packaging/deb/postinst" "$CONTROL_DIR/postinst"
install -m 0755 "$ROOT_DIR/packaging/deb/prerm" "$CONTROL_DIR/prerm"
install -m 0755 "$ROOT_DIR/packaging/deb/postrm" "$CONTROL_DIR/postrm"

sed -i "s/^Version: .*/Version: $VERSION/" "$CONTROL_DIR/control"
sed -i "s/^Architecture: .*/Architecture: $ARCH/" "$CONTROL_DIR/control"

dpkg-deb --build --root-owner-group "$PACKAGE_DIR" "$DEB_PATH"

printf '%s\n' "$DEB_PATH"
