# Installed Layout

The intended Linux package layout is:

```text
/usr/bin/peperspray
/usr/bin/pepersprayd
/etc/peperspray/config.toml
/etc/logrotate.d/peperspray
/var/log/peperspray/events.jsonl
/usr/lib/systemd/system/pepersprayd.service
```

Debian ownership and permissions:

- `/etc/peperspray/`: `root:root`, `0755`
- `/etc/peperspray/config.toml`: `root:root`, `0644` initially
- `/etc/logrotate.d/peperspray`: `root:root`, `0644`
- `/var/log/peperspray/`: `root:adm`, `0750`
- `/var/log/peperspray/events.jsonl`: `root:adm`, `0640`, created by `pepersprayd`
- `/usr/bin/peperspray`: `root:root`, executable
- `/usr/bin/pepersprayd`: `root:root`, executable

Debian packages use `root:adm` for `/var/log/peperspray` and
`events.jsonl`. The RPM package uses `root:root` for the same paths so the local
package does not depend on an `adm` group being present on Fedora/RHEL-family
systems.

The service runs as root by default because fanotify permission events and
policy enforcement require elevated privileges. The systemd unit applies a
sandbox profile (`ProtectSystem=strict`, `ProtectHome=read-only`, a reduced
`CapabilityBoundingSet`, and a `@system-service` syscall filter). Enforcement
depends on `CAP_SYS_ADMIN`, so re-verify fanotify still initializes if you
tighten the profile further.

The audit log holds sensitive process context (command lines, working
directories, executables, parent chains, and target credential paths), so it is
restricted to root-owned, non-world-readable permissions. Debian uses
`root:adm` with mode `0640`; RPM uses `root:root` with mode `0640`. The daemon
also creates the log with mode `0640` when it does not already exist.

`peperspray doctor` reports errors when installed config, log, or binary paths
are not root-owned, are group/world-writable, or when the log directory/audit log
is world-accessible. Missing optional protected preset paths are warnings.

The package installs a logrotate policy for `/var/log/peperspray/events.jsonl`.
It rotates daily, rotates early at 10 MiB, keeps 14 rotations, compresses older
logs, and uses `copytruncate` so the daemon does not need signal-based log
reopen support.

The package recommends `libnotify-bin` so `pepersprayd` can send best-effort
desktop notifications for denied reads with `notify-send`. Notifications are
throttled in memory by user, executable, protected group, and operation for five
minutes.

Delivering a notification runs `runuser` to enter the target user's session
bus, so the installed `pepersprayd.service` grants the privilege-changing
capabilities, the `@setuid` syscall group, and writable+executable memory that
`runuser` and PAM require. This is the documented tradeoff of running
notifications from a root daemon; the unit comments describe how to revert to a
stricter no-notification profile while keeping enforcement and logging intact.

## Package Lifecycle

Build a local package with:

```sh
packaging/build-deb.sh
```

The Debian builder emits a package for the host architecture by default. On
Linux ARM64 hosts this produces `arm64`; set `PEPERSPRAY_ARCH` only when you
need to override the package architecture.

Build a local RPM package on Fedora/RHEL-family systems with:

```sh
packaging/build-rpm.sh
```

The RPM builder emits a package for the host architecture by default, including
`aarch64` on Linux ARM64 hosts.

Build the RPM from a non-RPM host through a Fedora container with:

```sh
packaging/build-rpm-container.sh
```

Install it with:

```sh
cp ./target/debian/peperspray_0.1.4_amd64.deb /tmp/
sudo apt install /tmp/peperspray_0.1.4_amd64.deb
```

Remove package-managed files while keeping conffiles where dpkg normally keeps
them:

```sh
sudo apt remove peperspray
```

Purge package-managed config and runtime state:

```sh
sudo apt purge peperspray
```

The maintainer scripts stop and disable `pepersprayd.service` during removal and
remove `/etc/peperspray/config.toml`, `/etc/logrotate.d/peperspray`, and
`/var/log/peperspray/events.jsonl` during purge.

For a repeatable VM smoke test of this lifecycle, see
`docs/QEMU_PACKAGE_TESTING.md`, `packaging/qemu-test-deb.sh`, and
`packaging/qemu-test-rpm.sh`.
