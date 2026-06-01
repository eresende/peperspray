# Installed Layout

The intended Linux package layout is:

```text
/usr/bin/peperspray
/usr/bin/pepersprayd
/etc/peperspray/config.toml
/var/log/peperspray/events.jsonl
/lib/systemd/system/pepersprayd.service
```

Ownership and permissions:

- `/etc/peperspray/`: `root:root`, `0755`
- `/etc/peperspray/config.toml`: `root:root`, `0644` initially
- `/var/log/peperspray/`: `root:root`, `0755`
- `/var/log/peperspray/events.jsonl`: created by `pepersprayd`
- `/usr/bin/peperspray`: `root:root`, executable
- `/usr/bin/pepersprayd`: `root:root`, executable

The service runs as root by default because fanotify permission events and
policy enforcement require elevated privileges.

## Package Lifecycle

Build a local package with:

```sh
packaging/build-deb.sh
```

Install it with:

```sh
sudo apt install ./target/debian/peperspray_0.1.0_amd64.deb
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
remove `/etc/peperspray/config.toml` plus `/var/log/peperspray/events.jsonl`
during purge.

For a repeatable VM smoke test of this lifecycle, see
`docs/QEMU_PACKAGE_TESTING.md` and `packaging/qemu-test-deb.sh`.
