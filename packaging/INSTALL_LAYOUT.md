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

The package installs a logrotate policy for `/var/log/peperspray/events.jsonl`.
It rotates daily, rotates early at 10 MiB, keeps 14 rotations, compresses older
logs, and uses `copytruncate` so the daemon does not need signal-based log
reopen support.

The package recommends `libnotify-bin` so `pepersprayd` can send best-effort
desktop notifications for denied reads with `notify-send`. Notifications are
throttled in memory by user, executable, protected group, and operation for five
minutes.

## Package Lifecycle

Build a local package with:

```sh
packaging/build-deb.sh
```

Build a local RPM package on Fedora/RHEL-family systems with:

```sh
packaging/build-rpm.sh
```

Build the RPM from a non-RPM host through a Fedora container with:

```sh
packaging/build-rpm-container.sh
```

Install it with:

```sh
cp ./target/debian/peperspray_0.1.2_amd64.deb /tmp/
sudo apt install /tmp/peperspray_0.1.2_amd64.deb
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
