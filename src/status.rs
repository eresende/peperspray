use crate::config;
use serde::Serialize;

#[derive(Debug, Serialize)]
struct StatusOutput<'a> {
    schema_version: u32,
    platform: &'static str,
    backend: &'static str,
    mode: String,
    protected_users: usize,
    protected_groups: usize,
    allow_rules: usize,
    groups: &'a [config::ProtectedPathGroup],
    rules: &'a [config::AllowRule],
}

pub fn print_status(config: &config::Config) {
    println!("Mode: {}", config.mode);
    println!("Protected users: {}", config.users.len());
    println!("Protected groups: {}", config.protected_groups.len());
    println!("Allow rules: {}", config.allow_rules.len());
    println!();

    println!("Protected groups:");
    for group in &config.protected_groups {
        println!("  {}", group.name);

        for path in &group.paths {
            println!("    {}", path.display());
        }
    }

    println!();
    println!("Allow rules:");

    if config.allow_rules.is_empty() {
        println!("  <none>");
        return;
    }

    for rule in &config.allow_rules {
        println!("  {}", rule.name);
        println!("    uid:        {}", rule.uid);
        println!("    exe:        {}", rule.exe.display());
        println!("    path_group: {}", rule.path_group);
        println!(
            "    operation:  {}",
            rule.operation
                .map(|operation| operation.to_string())
                .unwrap_or_else(|| "<any>".to_string())
        );
        println!(
            "    parent_exe: {}",
            rule.parent_exe
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<none>".to_string())
        );
    }
}

pub fn status_to_json(config: &config::Config) -> anyhow::Result<String> {
    let output = StatusOutput {
        schema_version: 2,
        platform: std::env::consts::OS,
        backend: crate::backend_name(),
        mode: config.mode.to_string(),
        protected_users: config.users.len(),
        protected_groups: config.protected_groups.len(),
        allow_rules: config.allow_rules.len(),
        groups: &config.protected_groups,
        rules: &config.allow_rules,
    };

    Ok(serde_json::to_string_pretty(&output)?)
}

pub fn print_status_json(config: &config::Config) -> anyhow::Result<()> {
    println!("{}", status_to_json(config)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn status_to_json_outputs_summary() {
        let config = config::Config {
            mode: config::Mode::Learn,
            users: vec![config::ProtectedUser {
                uid: 1000,
                groups: vec!["aws".to_string()],
            }],
            protected_groups: vec![config::ProtectedPathGroup {
                name: "aws".to_string(),
                paths: vec![PathBuf::from("/home/alice/.aws")],
                patterns: Vec::new(),
            }],
            allow_rules: vec![config::AllowRule {
                name: "Allow AWS CLI".to_string(),
                uid: 1000,
                exe: PathBuf::from("/usr/bin/aws"),
                exe_sha256: None,
                path_group: "aws".to_string(),
                parent_exe: None,
                operation: None,
            }],
        };

        let json = status_to_json(&config).expect("status should serialize");

        assert!(json.contains("\"mode\": \"learn\""));
        assert!(json.contains("\"protected_users\": 1"));
        assert!(json.contains("\"protected_groups\": 1"));
        assert!(json.contains("\"allow_rules\": 1"));
        assert!(json.contains("\"name\": \"aws\""));
        assert!(json.contains("\"name\": \"Allow AWS CLI\""));
    }
}
