use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[test]
fn debian_control_declares_package_metadata() {
    let control = std::fs::read_to_string("packaging/deb/control").expect("control should exist");

    assert!(control.contains("Package: peperspray"));
    assert!(control.contains("Version: 0.1.2"));
    assert!(control.contains("Architecture: amd64"));
    assert!(control.contains("Depends: systemd, logrotate"));
    assert!(control.contains("Recommends: libnotify-bin"));
}

#[test]
fn maintainer_scripts_are_executable() {
    for path in [
        "packaging/deb/postinst",
        "packaging/deb/prerm",
        "packaging/deb/postrm",
        "packaging/build-deb.sh",
        "packaging/build-rpm.sh",
        "packaging/build-rpm-container.sh",
        "packaging/qemu-test-deb.sh",
        "packaging/qemu-test-rpm.sh",
        "packaging/qemu-test-privileged.sh",
    ] {
        let mode = std::fs::metadata(path)
            .unwrap_or_else(|err| panic!("{path} should exist: {err}"))
            .permissions()
            .mode();

        assert_ne!(mode & 0o111, 0, "{path} should be executable");
    }
}

#[test]
fn package_conffiles_tracks_config() {
    let conffiles =
        std::fs::read_to_string("packaging/deb/conffiles").expect("conffiles should exist");

    assert!(
        conffiles
            .lines()
            .any(|line| line == "/etc/peperspray/config.toml")
    );
    assert!(
        conffiles
            .lines()
            .any(|line| line == "/etc/logrotate.d/peperspray")
    );
}

#[test]
fn package_layout_files_exist() {
    for path in [
        "packaging/etc/peperspray/config.toml",
        "packaging/logrotate/peperspray",
        "packaging/systemd/pepersprayd.service",
        "packaging/INSTALL_LAYOUT.md",
        "packaging/rpm/peperspray.spec",
        "packaging/rpm/peperspray.logrotate",
        "docs/QEMU_PACKAGE_TESTING.md",
        "packaging/build-rpm-container.sh",
        "packaging/qemu-test-rpm.sh",
        "packaging/qemu-test-privileged.sh",
    ] {
        assert!(Path::new(path).exists(), "{path} should exist");
    }
}

#[test]
fn qemu_deb_test_exercises_upgrade_permission_repair() {
    let script =
        std::fs::read_to_string("packaging/qemu-test-deb.sh").expect("qemu deb test should exist");

    assert!(
        script.contains("checking upgrade permission repair"),
        "QEMU deb smoke test should include upgrade permission repair coverage"
    );
    assert!(
        script.contains("sudo DEBIAN_FRONTEND=noninteractive dpkg -i /tmp/peperspray.deb"),
        "QEMU deb smoke test should reconfigure the installed package"
    );
    assert!(
        script.contains("chmod 0644 /var/log/peperspray/events.jsonl"),
        "QEMU deb smoke test should simulate the old world-readable audit log"
    );
}

#[test]
fn rpm_spec_declares_package_layout_and_scriptlets() {
    let spec =
        std::fs::read_to_string("packaging/rpm/peperspray.spec").expect("rpm spec should exist");

    for expected in [
        "Name:           peperspray",
        "Requires:       systemd",
        "Requires:       logrotate",
        "BuildRequires:  systemd-rpm-macros",
        "%systemd_post pepersprayd.service",
        "%config(noreplace) %{_sysconfdir}/peperspray/config.toml",
        "%config(noreplace) %{_sysconfdir}/logrotate.d/peperspray",
        "%ghost %attr(0640,root,root) %{_localstatedir}/log/peperspray/events.jsonl",
    ] {
        assert!(
            spec.contains(expected),
            "rpm spec should contain {expected}"
        );
    }
}

#[test]
fn rpm_logrotate_policy_uses_portable_root_group() {
    let policy = std::fs::read_to_string("packaging/rpm/peperspray.logrotate")
        .expect("rpm logrotate policy should exist");

    assert!(policy.contains("/var/log/peperspray/events.jsonl"));
    assert!(policy.contains("create 0640 root root"));
    assert!(!policy.contains("root adm"));
}

#[test]
fn rpm_container_builder_uses_fedora_and_delegates_to_rpm_builder() {
    let script = std::fs::read_to_string("packaging/build-rpm-container.sh")
        .expect("rpm container builder should exist");

    for expected in [
        "RPM_BUILD_IMAGE:-fedora:44",
        "CONTAINER_ENGINE:-docker",
        "dnf install -y rpm-build systemd-rpm-macros rust cargo gcc make findutils",
        "packaging/build-rpm.sh",
    ] {
        assert!(
            script.contains(expected),
            "container RPM builder should contain {expected}"
        );
    }
}

#[test]
fn qemu_rpm_test_exercises_lifecycle_and_reinstall_repair() {
    let script =
        std::fs::read_to_string("packaging/qemu-test-rpm.sh").expect("qemu rpm test should exist");

    for expected in [
        "sudo dnf install -y /tmp/peperspray.rpm",
        "checking reinstall permission repair",
        "sudo rpm -Uvh --replacepkgs /tmp/peperspray.rpm",
        "peperspray-0.1.1-1.fc44.x86_64.rpm",
        "sudo dnf remove -y peperspray",
        "test \"$(sudo stat -c %U:%G /var/log/peperspray)\" = \"root:root\"",
    ] {
        assert!(
            script.contains(expected),
            "QEMU RPM smoke test should contain {expected}"
        );
    }
}

#[test]
fn logrotate_policy_rotates_runtime_log() {
    let policy = std::fs::read_to_string("packaging/logrotate/peperspray")
        .expect("logrotate policy should exist");

    assert!(policy.contains("/var/log/peperspray/events.jsonl"));
    assert!(policy.contains("daily"));
    assert!(policy.contains("maxsize 10M"));
    assert!(policy.contains("rotate 14"));
    assert!(policy.contains("copytruncate"));
    assert!(policy.contains("compress"));
}

#[test]
fn logrotate_policy_recreates_log_without_world_access() {
    let policy = std::fs::read_to_string("packaging/logrotate/peperspray")
        .expect("logrotate policy should exist");

    // The audit log carries sensitive process context, so rotation must not
    // recreate it world-readable.
    assert!(
        policy.contains("create 0640 root adm"),
        "logrotate should recreate the log as 0640 root adm"
    );
    assert!(!policy.contains("create 0644"));
}

#[test]
fn postinst_creates_audit_log_without_world_access() {
    let postinst =
        std::fs::read_to_string("packaging/deb/postinst").expect("postinst should exist");

    assert!(
        postinst
            .contains("install -o root -g adm -m 0640 /dev/null /var/log/peperspray/events.jsonl"),
        "postinst should create the audit log as 0640 root adm"
    );
    assert!(
        postinst.contains("install -d -o root -g adm -m 0750 /var/log/peperspray"),
        "postinst should create the log dir as 0750 root adm"
    );
    assert!(
        postinst.contains("chown root:adm /var/log/peperspray/events.jsonl"),
        "postinst should repair existing audit log ownership"
    );
    assert!(
        postinst.contains("chmod 0640 /var/log/peperspray/events.jsonl"),
        "postinst should repair existing audit log mode"
    );
}

#[test]
fn postinst_repairs_preexisting_world_readable_audit_log() {
    let postinst =
        std::fs::read_to_string("packaging/deb/postinst").expect("postinst should exist");

    let has_create_guard = postinst
        .lines()
        .any(|line| line.trim() == "if [ ! -e /var/log/peperspray/events.jsonl ]; then");
    let has_unconditional_chmod = postinst
        .lines()
        .any(|line| line.trim() == "chmod 0640 /var/log/peperspray/events.jsonl");

    assert!(
        has_create_guard && has_unconditional_chmod,
        "postinst must chmod the audit log even when it already exists"
    );
}

#[test]
fn systemd_unit_applies_sandboxing() {
    let unit = std::fs::read_to_string("packaging/systemd/pepersprayd.service")
        .expect("systemd unit should exist");

    for directive in [
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "ReadWritePaths=/var/log/peperspray",
        "SystemCallFilter=@system-service",
        "UMask=0027",
    ] {
        assert!(
            unit.lines().any(|line| line.trim() == directive),
            "systemd unit should set {directive}"
        );
    }

    let capability_line = unit
        .lines()
        .find(|line| line.trim().starts_with("CapabilityBoundingSet="))
        .expect("systemd unit should restrict the capability bounding set");

    for capability in ["CAP_SYS_ADMIN", "CAP_DAC_READ_SEARCH", "CAP_SYS_PTRACE"] {
        assert!(
            capability_line.contains(capability),
            "systemd unit should keep {capability} for fanotify and process inspection"
        );
    }

    // The guard must come back after a clean stop/kill, not only on failure,
    // otherwise the host is left unprotected.
    assert!(
        unit.lines().any(|line| line.trim() == "Restart=always"),
        "systemd unit should restart always"
    );

    assert!(
        !unit
            .lines()
            .any(|line| line.trim().starts_with("ProtectProc=")),
        "daemon must be able to inspect /proc/<pid> for non-root fanotify events"
    );
}

#[test]
fn systemd_unit_uses_valid_documentation_reference() {
    let unit = std::fs::read_to_string("packaging/systemd/pepersprayd.service")
        .expect("systemd unit should exist");
    let documentation = unit
        .lines()
        .find_map(|line| line.strip_prefix("Documentation="))
        .expect("systemd unit should declare documentation");

    assert!(
        documentation.starts_with("https://")
            || documentation.starts_with("http://")
            || documentation.starts_with("man:")
            || documentation.starts_with("info:"),
        "unexpected Documentation= value: {documentation}"
    );
}
