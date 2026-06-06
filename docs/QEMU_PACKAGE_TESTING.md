# QEMU Package Testing

Use QEMU to validate Linux packages in real booted systems. These are package
lifecycle tests that Docker cannot accurately cover because
`pepersprayd` depends on systemd, root-owned service execution, fanotify, and
normal `/etc` plus `/var/log` behavior.

## Prerequisites

On the host:

```sh
sudo apt install qemu-system-x86 qemu-utils cloud-image-utils openssh-client
```

Download an Ubuntu 24.04 cloud image:

```sh
wget https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
```

Build the local Debian package:

```sh
packaging/build-deb.sh
```

Build the local RPM package on a Fedora/RHEL-family host with `rpmbuild`
installed:

```sh
packaging/build-rpm.sh
```

Or build the RPM from an Ubuntu/Debian host through a Fedora container:

```sh
packaging/build-rpm-container.sh
```

The container build only produces the RPM artifact. Use the QEMU RPM smoke test
below for systemd/package lifecycle validation.

## Debian / Ubuntu Run

```sh
packaging/qemu-test-deb.sh \
  --image ./noble-server-cloudimg-amd64.img \
  --deb ./target/debian/peperspray_0.1.2_amd64.deb
```

The script creates a temporary overlay under `target/qemu-deb-test`, boots the
cloud image with SSH on `127.0.0.1:2222`, installs the package, checks service
startup, verifies installed paths, simulates an upgrade from older log
permissions, runs remove, then runs purge.

The runner uses KVM when `/dev/kvm` is available and falls back to TCG
otherwise. Set `QEMU_ACCEL=kvm` or `QEMU_ACCEL=tcg` to force one mode.

The QEMU lifecycle runners currently document and exercise x86_64 cloud images.
ARM64 release packages are built separately by the release workflow; ARM64 QEMU
lifecycle coverage is intentionally deferred.

## Debian / Ubuntu Checks

The smoke test verifies:

- `/usr/bin/peperspray` and `/usr/bin/pepersprayd` are installed.
- `/etc/peperspray/config.toml` exists as root-owned `0644`.
- `/etc/logrotate.d/peperspray` exists as root-owned `0644` and passes
  `logrotate --debug`.
- `/var/log/peperspray` exists as `root:adm` with mode `0750`.
- `/var/log/peperspray/events.jsonl` exists as `root:adm` with mode `0640`.
- `pepersprayd.service` is installed and can start under systemd.
- `peperspray service status` can reach systemd.
- Reinstalling the package repairs an old world-readable audit log and log
  directory back to `root:adm`, `0750` for the directory, and `0640` for the
  JSONL log.
- `apt remove peperspray` removes binaries but leaves conffiles.
- `apt purge peperspray` removes the config, logrotate policy, and runtime log.

## RPM / Fedora Run

Use a Fedora cloud image and the RPM package built by `packaging/build-rpm.sh`
or `packaging/build-rpm-container.sh`:

```sh
packaging/qemu-test-rpm.sh \
  --image ./Fedora-Cloud-Base.qcow2 \
  --rpm ./target/rpm/RPMS/x86_64/peperspray-0.1.2-1.fc44.x86_64.rpm
```

The RPM smoke test verifies:

- `/usr/bin/peperspray` and `/usr/bin/pepersprayd` are installed.
- `/etc/peperspray/config.toml` exists as root-owned `0644`.
- `/etc/logrotate.d/peperspray` exists as root-owned `0644` and passes
  `logrotate --debug`.
- `/var/log/peperspray` exists as `root:root` with mode `0750`.
- `/var/log/peperspray/events.jsonl` exists as `root:root` with mode `0640`.
- `pepersprayd.service` is installed and can start under systemd.
- `peperspray service status` can reach systemd.
- Reinstalling the package repairs an old world-readable audit log and log
  directory back to `root:root`, `0750` for the directory, and `0640` for the
  JSONL log.
- `dnf remove peperspray` removes binaries, service metadata, and the runtime
  log.

## Notes

The QEMU package smoke test does not run the ignored privileged fanotify or
path-identity tests. Use the dedicated privileged-test runner when validating
real read blocking and current path-alias behavior:

```sh
packaging/qemu-test-privileged.sh --image ./noble-server-cloudimg-amd64.img
```

The privileged runner builds `pepersprayd`, `privileged_fanotify`, and
`privileged_path_identity` on the host, copies those artifacts into the VM, then
runs the ignored tests with root privileges. This avoids installing Rust in the
guest while still exercising the guest kernel, fanotify permission events, bind
mounts, and mount namespaces.

You can still run the tests manually inside an Ubuntu 24.04 environment:

```sh
cargo test --test privileged_fanotify --no-run
sudo "$(find target/debug/deps -maxdepth 1 -type f -executable -name 'privileged_fanotify-*' | head -n1)" --ignored --nocapture
cargo test --test privileged_path_identity --no-run
sudo "$(find target/debug/deps -maxdepth 1 -type f -executable -name 'privileged_path_identity-*' | head -n1)" --ignored --nocapture
```
