use crate::{backend_name, config};
use serde::Serialize;
use std::path::Path;

const DEFAULT_CONFIG_DIR: &str = "/etc/peperspray";
const DEFAULT_CLI_BINARY: &str = "/usr/bin/peperspray";
const DEFAULT_DAEMON_BINARY: &str = "/usr/bin/pepersprayd";

#[derive(Debug, Serialize)]
struct DoctorOutput {
    schema_version: u32,
    platform: &'static str,
    backend: &'static str,
    ok: bool,
    errors: usize,
    warnings: usize,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize)]
struct DoctorCheck {
    name: String,
    severity: DoctorSeverity,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum DoctorSeverity {
    Ok,
    Warning,
    Error,
}

pub fn run(config_path: &Path, log_file: &Path, json: bool) -> anyhow::Result<bool> {
    let mut checks = Vec::new();

    checks.push(path_exists_check("config_exists", config_path));
    checks.push(path_exists_check(
        "log_parent_exists",
        log_file.parent().unwrap_or(Path::new(".")),
    ));
    checks.push(backend_check());
    checks.extend(tamper_checks(config_path, log_file));

    match config::load_config(config_path) {
        Ok(parsed_config) => {
            let errors = config::validate_config(&parsed_config);
            checks.push(DoctorCheck {
                name: "config_valid".to_string(),
                severity: if errors.is_empty() {
                    DoctorSeverity::Ok
                } else {
                    DoctorSeverity::Error
                },
                message: if errors.is_empty() {
                    "config parses and validates".to_string()
                } else {
                    errors.join("; ")
                },
            });

            for group in &parsed_config.protected_groups {
                for path in &group.paths {
                    if path.is_absolute() && !path.exists() {
                        checks.push(DoctorCheck {
                            name: "protected_path_missing".to_string(),
                            severity: DoctorSeverity::Warning,
                            message: format!(
                                "{} path {} does not exist",
                                group.name,
                                path.display()
                            ),
                        });
                    }
                }
            }
        }
        Err(err) => checks.push(DoctorCheck {
            name: "config_valid".to_string(),
            severity: DoctorSeverity::Error,
            message: err.to_string(),
        }),
    }

    let errors = doctor_error_count(&checks);
    let warnings = doctor_warning_count(&checks);
    let ok = doctor_ok(&checks);
    let output = DoctorOutput {
        schema_version: 2,
        platform: std::env::consts::OS,
        backend: backend_name(),
        ok,
        errors,
        warnings,
        checks,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Platform: {}", output.platform);
        println!("Backend: {}", output.backend);
        for check in &output.checks {
            let status = match check.severity {
                DoctorSeverity::Ok => "ok",
                DoctorSeverity::Warning => "warn",
                DoctorSeverity::Error => "fail",
            };
            println!("{status}: {}: {}", check.name, check.message);
        }
    }

    Ok(ok)
}

fn tamper_checks(config_path: &Path, log_file: &Path) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();

    checks.push(owned_by_root_check("config_owner", config_path));
    checks.push(not_group_or_world_writable_check(
        "config_not_writable_by_others",
        config_path,
    ));

    let config_dir = config_path
        .parent()
        .unwrap_or(Path::new(DEFAULT_CONFIG_DIR));
    checks.push(owned_by_root_check("config_dir_owner", config_dir));
    checks.push(not_group_or_world_writable_check(
        "config_dir_not_writable_by_others",
        config_dir,
    ));

    let log_dir = log_file.parent().unwrap_or(Path::new("."));
    checks.push(owned_by_root_check("log_dir_owner", log_dir));
    checks.push(not_group_or_world_writable_check(
        "log_dir_not_writable_by_others",
        log_dir,
    ));
    checks.push(not_world_accessible_check(
        "log_dir_not_world_accessible",
        log_dir,
    ));

    if log_file.exists() {
        checks.push(owned_by_root_check("log_file_owner", log_file));
        checks.push(not_group_or_world_writable_check(
            "log_file_not_writable_by_others",
            log_file,
        ));
        checks.push(not_world_accessible_check(
            "log_file_not_world_accessible",
            log_file,
        ));
    }

    for (name, path) in [
        ("cli_binary", Path::new(DEFAULT_CLI_BINARY)),
        ("daemon_binary", Path::new(DEFAULT_DAEMON_BINARY)),
    ] {
        checks.push(owned_by_root_check(&format!("{name}_owner"), path));
        checks.push(not_group_or_world_writable_check(
            &format!("{name}_not_writable_by_others"),
            path,
        ));
    }

    checks
}

fn doctor_error_count(checks: &[DoctorCheck]) -> usize {
    checks
        .iter()
        .filter(|check| check.severity == DoctorSeverity::Error)
        .count()
}

fn doctor_warning_count(checks: &[DoctorCheck]) -> usize {
    checks
        .iter()
        .filter(|check| check.severity == DoctorSeverity::Warning)
        .count()
}

fn doctor_ok(checks: &[DoctorCheck]) -> bool {
    doctor_error_count(checks) == 0
}

fn path_exists_check(name: &str, path: &Path) -> DoctorCheck {
    DoctorCheck {
        name: name.to_string(),
        severity: if path.exists() {
            DoctorSeverity::Ok
        } else {
            DoctorSeverity::Error
        },
        message: if path.exists() {
            format!("{} exists", path.display())
        } else {
            format!("{} does not exist", path.display())
        },
    }
}

#[cfg(unix)]
fn owned_by_root_check(name: &str, path: &Path) -> DoctorCheck {
    use std::os::unix::fs::MetadataExt;

    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            let uid = metadata.uid();
            DoctorCheck {
                name: name.to_string(),
                severity: if uid == 0 {
                    DoctorSeverity::Ok
                } else {
                    DoctorSeverity::Error
                },
                message: if uid == 0 {
                    format!("{} is owned by root", path.display())
                } else {
                    format!("{} is owned by uid {uid}, expected root", path.display())
                },
            }
        }
        Err(err) => metadata_error_check(name, path, err),
    }
}

#[cfg(not(unix))]
fn owned_by_root_check(name: &str, path: &Path) -> DoctorCheck {
    DoctorCheck {
        name: name.to_string(),
        severity: DoctorSeverity::Warning,
        message: format!(
            "{} ownership checks are not supported on this platform",
            path.display()
        ),
    }
}

#[cfg(unix)]
fn not_group_or_world_writable_check(name: &str, path: &Path) -> DoctorCheck {
    use std::os::unix::fs::PermissionsExt;

    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            let mode = metadata.permissions().mode() & 0o777;
            let unsafe_bits = mode & 0o022;
            DoctorCheck {
                name: name.to_string(),
                severity: if unsafe_bits == 0 {
                    DoctorSeverity::Ok
                } else {
                    DoctorSeverity::Error
                },
                message: if unsafe_bits == 0 {
                    format!(
                        "{} mode {:03o} is not group/world-writable",
                        path.display(),
                        mode
                    )
                } else {
                    format!(
                        "{} mode {:03o} is group/world-writable; clear bits {:03o}",
                        path.display(),
                        mode,
                        unsafe_bits
                    )
                },
            }
        }
        Err(err) => metadata_error_check(name, path, err),
    }
}

#[cfg(not(unix))]
fn not_group_or_world_writable_check(name: &str, path: &Path) -> DoctorCheck {
    DoctorCheck {
        name: name.to_string(),
        severity: DoctorSeverity::Warning,
        message: format!(
            "{} mode checks are not supported on this platform",
            path.display()
        ),
    }
}

#[cfg(unix)]
fn not_world_accessible_check(name: &str, path: &Path) -> DoctorCheck {
    use std::os::unix::fs::PermissionsExt;

    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            let mode = metadata.permissions().mode() & 0o777;
            let unsafe_bits = mode & 0o007;
            DoctorCheck {
                name: name.to_string(),
                severity: if unsafe_bits == 0 {
                    DoctorSeverity::Ok
                } else {
                    DoctorSeverity::Error
                },
                message: if unsafe_bits == 0 {
                    format!(
                        "{} mode {:03o} is not world-accessible",
                        path.display(),
                        mode
                    )
                } else {
                    format!(
                        "{} mode {:03o} is world-accessible; clear bits {:03o}",
                        path.display(),
                        mode,
                        unsafe_bits
                    )
                },
            }
        }
        Err(err) => metadata_error_check(name, path, err),
    }
}

#[cfg(not(unix))]
fn not_world_accessible_check(name: &str, path: &Path) -> DoctorCheck {
    DoctorCheck {
        name: name.to_string(),
        severity: DoctorSeverity::Warning,
        message: format!(
            "{} mode checks are not supported on this platform",
            path.display()
        ),
    }
}

fn metadata_error_check(name: &str, path: &Path, err: std::io::Error) -> DoctorCheck {
    DoctorCheck {
        name: name.to_string(),
        severity: DoctorSeverity::Error,
        message: format!("failed to inspect {}: {err}", path.display()),
    }
}

fn backend_check() -> DoctorCheck {
    let backend = backend_name();
    let ok = cfg!(target_os = "linux");
    let message = if ok {
        "Linux fanotify backend is available in this build".to_string()
    } else {
        format!("{backend} backend requires a separately signed system component")
    };

    DoctorCheck {
        name: "backend_available".to_string(),
        severity: if ok {
            DoctorSeverity::Ok
        } else {
            DoctorSeverity::Error
        },
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn warning_checks_do_not_make_doctor_fail() {
        let checks = vec![
            DoctorCheck {
                name: "config_valid".to_string(),
                severity: DoctorSeverity::Ok,
                message: "ok".to_string(),
            },
            DoctorCheck {
                name: "protected_path_missing".to_string(),
                severity: DoctorSeverity::Warning,
                message: "optional path missing".to_string(),
            },
        ];

        assert_eq!(doctor_error_count(&checks), 0);
        assert_eq!(doctor_warning_count(&checks), 1);
        assert!(doctor_ok(&checks));
    }

    #[test]
    fn error_checks_make_doctor_fail() {
        let checks = vec![DoctorCheck {
            name: "config_valid".to_string(),
            severity: DoctorSeverity::Error,
            message: "invalid config".to_string(),
        }];

        assert_eq!(doctor_error_count(&checks), 1);
        assert!(!doctor_ok(&checks));
    }

    #[cfg(unix)]
    #[test]
    fn writable_by_group_or_world_is_an_error() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "mode = \"learn\"").expect("config should be written");

        let mut permissions = std::fs::metadata(&path)
            .expect("metadata should be readable")
            .permissions();
        permissions.set_mode(0o664);
        std::fs::set_permissions(&path, permissions).expect("permissions should be updated");

        let check = not_group_or_world_writable_check("config_not_writable_by_others", &path);

        assert_eq!(check.severity, DoctorSeverity::Error);
        assert!(check.message.contains("group/world-writable"));
    }

    #[cfg(unix)]
    #[test]
    fn non_world_accessible_log_file_is_ok() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let path = dir.path().join("events.jsonl");
        std::fs::write(&path, "").expect("log should be written");

        let mut permissions = std::fs::metadata(&path)
            .expect("metadata should be readable")
            .permissions();
        permissions.set_mode(0o640);
        std::fs::set_permissions(&path, permissions).expect("permissions should be updated");

        let check = not_world_accessible_check("log_file_not_world_accessible", &path);

        assert_eq!(check.severity, DoctorSeverity::Ok);
    }

    #[cfg(unix)]
    #[test]
    fn world_accessible_log_file_is_an_error() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let path = dir.path().join("events.jsonl");
        std::fs::write(&path, "").expect("log should be written");

        let mut permissions = std::fs::metadata(&path)
            .expect("metadata should be readable")
            .permissions();
        permissions.set_mode(0o644);
        std::fs::set_permissions(&path, permissions).expect("permissions should be updated");

        let check = not_world_accessible_check("log_file_not_world_accessible", &path);

        assert_eq!(check.severity, DoctorSeverity::Error);
        assert!(check.message.contains("world-accessible"));
    }
}
