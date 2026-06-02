# QEMU Package Testing

Use QEMU/KVM to validate the Debian package in a real booted Ubuntu system.
This is the package lifecycle test that Docker cannot accurately cover because
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

Build the local package:

```sh
packaging/build-deb.sh
```

## Run

```sh
packaging/qemu-test-deb.sh \
  --image ./noble-server-cloudimg-amd64.img \
  --deb ./target/debian/peperspray_0.1.0_amd64.deb
```

The script creates a temporary overlay under `target/qemu-deb-test`, boots the
cloud image with SSH on `127.0.0.1:2222`, installs the package, checks service
startup, verifies installed paths, runs remove, then runs purge.

## Checks

The smoke test verifies:

- `/usr/bin/peperspray` and `/usr/bin/pepersprayd` are installed.
- `/etc/peperspray/config.toml` exists as root-owned `0644`.
- `/etc/logrotate.d/peperspray` exists as root-owned `0644` and passes
  `logrotate --debug`.
- `/var/log/peperspray/events.jsonl` exists.
- `pepersprayd.service` is installed and can start under systemd.
- `peperspray service status` can reach systemd.
- `apt remove peperspray` removes binaries but leaves conffiles.
- `apt purge peperspray` removes the config, logrotate policy, and runtime log.

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
