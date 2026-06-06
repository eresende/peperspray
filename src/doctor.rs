use crate::{backend_name, config};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
struct DoctorOutput {
    schema_version: u32,
    platform: &'static str,
    backend: &'static str,
    ok: bool,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize)]
struct DoctorCheck {
    name: String,
    ok: bool,
    message: String,
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
                ok: errors.is_empty(),
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
                            ok: false,
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
            ok: false,
            message: err.to_string(),
        }),
    }

    let ok = checks.iter().all(|check| check.ok);
    let output = DoctorOutput {
        schema_version: 2,
        platform: std::env::consts::OS,
        backend: backend_name(),
        ok,
        checks,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Platform: {}", output.platform);
        println!("Backend: {}", output.backend);
        for check in &output.checks {
            let status = if check.ok { "ok" } else { "fail" };
            println!("{status}: {}: {}", check.name, check.message);
        }
    }

    Ok(ok)
}

fn path_exists_check(name: &str, path: &Path) -> DoctorCheck {
    DoctorCheck {
        name: name.to_string(),
        ok: path.exists(),
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
        ok,
        message,
    }
}
