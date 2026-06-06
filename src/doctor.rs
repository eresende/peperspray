use crate::{backend_name, config};
use serde::Serialize;
use std::path::Path;

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
}
