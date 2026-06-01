use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[test]
fn debian_control_declares_package_metadata() {
    let control = std::fs::read_to_string("packaging/deb/control").expect("control should exist");

    assert!(control.contains("Package: peperspray"));
    assert!(control.contains("Version: 0.1.0"));
    assert!(control.contains("Architecture: amd64"));
    assert!(control.contains("Depends: systemd"));
}

#[test]
fn maintainer_scripts_are_executable() {
    for path in [
        "packaging/deb/postinst",
        "packaging/deb/prerm",
        "packaging/deb/postrm",
        "packaging/build-deb.sh",
        "packaging/qemu-test-deb.sh",
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
}

#[test]
fn package_layout_files_exist() {
    for path in [
        "packaging/etc/peperspray/config.toml",
        "packaging/systemd/pepersprayd.service",
        "packaging/INSTALL_LAYOUT.md",
        "docs/QEMU_PACKAGE_TESTING.md",
    ] {
        assert!(Path::new(path).exists(), "{path} should exist");
    }
}
