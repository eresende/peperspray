use crate::event::Operation;
use crate::paths;
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
pub struct SetupOutput {
    output: PathBuf,
    uid: u32,
    written: bool,
    detected_tools: Vec<SetupDetectedToolOutput>,
    skipped_tools: Vec<SetupSkippedToolOutput>,
}

#[derive(Debug, Serialize)]
struct SetupDetectedToolOutput {
    command: String,
    rule_name: String,
    path_group: String,
    exe: PathBuf,
}

#[derive(Debug, Serialize)]
struct SetupSkippedToolOutput {
    command: String,
    rule_name: String,
    path_group: String,
    reason: String,
}

#[derive(Debug, Clone, Copy)]
pub struct SetupTool {
    command: &'static str,
    rule_name: &'static str,
    path_group: &'static str,
}

const SETUP_TOOLS: &[SetupTool] = &[
    SetupTool {
        command: "aws",
        rule_name: "Allow AWS CLI",
        path_group: "aws",
    },
    SetupTool {
        command: "ssh",
        rule_name: "Allow SSH client",
        path_group: "ssh",
    },
    SetupTool {
        command: "gh",
        rule_name: "Allow GitHub CLI",
        path_group: "github",
    },
    SetupTool {
        command: "gcloud",
        rule_name: "Allow Google Cloud CLI",
        path_group: "gcloud",
    },
    SetupTool {
        command: "docker",
        rule_name: "Allow Docker CLI",
        path_group: "docker",
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedTool {
    rule_name: String,
    exe: PathBuf,
    path_group: String,
}

#[derive(Debug, Clone)]
pub struct SetupToolDetection {
    tool: SetupTool,
    exe: Option<PathBuf>,
}

pub fn current_uid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

pub fn detect_setup_tool_statuses() -> Vec<SetupToolDetection> {
    SETUP_TOOLS
        .iter()
        .map(|tool| {
            let exe = which::which(tool.command)
                .ok()
                .map(|path| paths::normalize_path(&path));

            SetupToolDetection { tool: *tool, exe }
        })
        .collect()
}

pub fn detected_tools_from_statuses(statuses: &[SetupToolDetection]) -> Vec<DetectedTool> {
    statuses
        .iter()
        .filter_map(|status| {
            let exe = status.exe.clone()?;

            Some(DetectedTool {
                rule_name: status.tool.rule_name.to_string(),
                exe,
                path_group: status.tool.path_group.to_string(),
            })
        })
        .collect()
}

pub fn starter_config_toml_with_tools(uid: u32, tools: &[DetectedTool]) -> String {
    let protected_groups = starter_protected_groups_toml();
    let allow_rules = starter_allow_rules_toml(uid, tools);

    let mut toml = format!(
        r#"mode = "learn"

[[users]]
uid = {uid}
groups = ["aws", "ssh", "github", "gcloud", "docker"]

{protected_groups}
"#
    );

    if !allow_rules.is_empty() {
        toml.push('\n');
        toml.push_str(&allow_rules);
        toml.push('\n');
    }

    toml
}

fn starter_protected_groups_toml() -> String {
    [
        r#"[[protected_groups]]
name = "aws"
paths = ["~/.aws"]"#,
        r#"[[protected_groups]]
name = "ssh"
paths = ["~/.ssh"]"#,
        r#"[[protected_groups]]
name = "github"
paths = ["~/.config/gh", "~/.git-credentials", "~/.netrc"]"#,
        r#"[[protected_groups]]
name = "gcloud"
paths = ["~/.config/gcloud"]"#,
        r#"[[protected_groups]]
name = "docker"
paths = ["~/.docker"]"#,
    ]
    .join("\n\n")
}

fn starter_allow_rules_toml(uid: u32, tools: &[DetectedTool]) -> String {
    tools
        .iter()
        .map(|tool| {
            format!(
                r#"[[allow_rules]]
name = "{}"
uid = {}
exe = "{}"
path_group = "{}"
operation = "{}""#,
                tool.rule_name,
                uid,
                tool.exe.display(),
                tool.path_group,
                Operation::OpenRead
            )
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}

pub fn write_starter_config_with_tools(
    path: &Path,
    uid: u32,
    tools: &[DetectedTool],
    force: bool,
) -> anyhow::Result<()> {
    if path.exists() && !force {
        anyhow::bail!(
            "{} already exists; use --force to overwrite it",
            path.display()
        );
    }

    std::fs::write(path, starter_config_toml_with_tools(uid, tools))?;

    Ok(())
}

pub fn print_setup_tool_detection(statuses: &[SetupToolDetection]) {
    let detected: Vec<&SetupToolDetection> = statuses
        .iter()
        .filter(|status| status.exe.is_some())
        .collect();

    let skipped: Vec<&SetupToolDetection> = statuses
        .iter()
        .filter(|status| status.exe.is_none())
        .collect();

    println!("Detected tools:");

    if detected.is_empty() {
        println!("  <none>");
    } else {
        for status in detected {
            let exe = status.exe.as_ref().expect("detected tool should have exe");
            println!("  {:<7} {}", status.tool.command, exe.display());
        }
    }

    println!();
    println!("Skipped tools:");

    if skipped.is_empty() {
        println!("  <none>");
    } else {
        for status in skipped {
            println!("  {:<7} not found in PATH", status.tool.command);
        }
    }

    println!();
}

pub fn setup_output_from_statuses(
    output: PathBuf,
    uid: u32,
    written: bool,
    statuses: &[SetupToolDetection],
) -> SetupOutput {
    let detected_tools = statuses
        .iter()
        .filter_map(|status| {
            let exe = status.exe.clone()?;

            Some(SetupDetectedToolOutput {
                command: status.tool.command.to_string(),
                rule_name: status.tool.rule_name.to_string(),
                path_group: status.tool.path_group.to_string(),
                exe,
            })
        })
        .collect();

    let skipped_tools = statuses
        .iter()
        .filter(|status| status.exe.is_none())
        .map(|status| SetupSkippedToolOutput {
            command: status.tool.command.to_string(),
            rule_name: status.tool.rule_name.to_string(),
            path_group: status.tool.path_group.to_string(),
            reason: "not found in PATH".to_string(),
        })
        .collect();

    SetupOutput {
        output,
        uid,
        written,
        detected_tools,
        skipped_tools,
    }
}

pub fn setup_output_to_json(output: &SetupOutput) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(output)?)
}

pub fn print_setup_output_json(output: &SetupOutput) -> anyhow::Result<()> {
    println!("{}", setup_output_to_json(output)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starter_config_contains_uid_and_default_groups() {
        let tools = [
            DetectedTool {
                rule_name: "Allow AWS CLI".to_string(),
                exe: PathBuf::from("/usr/bin/aws"),
                path_group: "aws".to_string(),
            },
            DetectedTool {
                rule_name: "Allow SSH client".to_string(),
                exe: PathBuf::from("/usr/bin/ssh"),
                path_group: "ssh".to_string(),
            },
        ];

        let toml = starter_config_toml_with_tools(1000, &tools);

        assert!(toml.contains("uid = 1000"));
        assert!(toml.contains("groups = [\"aws\", \"ssh\", \"github\", \"gcloud\", \"docker\"]"));
        assert!(toml.contains("paths = [\"~/.aws\"]"));
        assert!(toml.contains("paths = [\"~/.ssh\"]"));
        assert!(toml.contains("name = \"Allow AWS CLI\""));
        assert!(toml.contains("name = \"Allow SSH client\""));
        assert!(toml.contains("operation = \"open_read\""));
    }

    #[test]
    fn starter_config_parses_as_config() {
        let tools = [DetectedTool {
            rule_name: "Allow SSH client".to_string(),
            exe: PathBuf::from("/usr/bin/ssh"),
            path_group: "ssh".to_string(),
        }];

        let toml = starter_config_toml_with_tools(1000, &tools);

        let config: crate::config::Config =
            toml::from_str(&toml).expect("starter config should parse");

        assert_eq!(config.mode, crate::config::Mode::Learn);
        assert_eq!(config.users.len(), 1);
        assert_eq!(config.protected_groups.len(), 5);
        assert_eq!(config.allow_rules.len(), 1);
    }

    #[test]
    fn write_starter_config_writes_file() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let path = dir.path().join("config.toml");

        let tools = [DetectedTool {
            rule_name: "Allow SSH client".to_string(),
            exe: PathBuf::from("/usr/bin/ssh"),
            path_group: "ssh".to_string(),
        }];

        write_starter_config_with_tools(&path, 1000, &tools, false)
            .expect("starter config should be written");

        let contents = std::fs::read_to_string(&path).expect("config should be readable");

        assert!(contents.contains("uid = 1000"));
        assert!(contents.contains("mode = \"learn\""));
        assert!(contents.contains("Allow SSH client"));
    }

    #[test]
    fn write_starter_config_refuses_overwrite_without_force() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let path = dir.path().join("config.toml");

        let tools = [DetectedTool {
            rule_name: "Allow SSH client".to_string(),
            exe: PathBuf::from("/usr/bin/ssh"),
            path_group: "ssh".to_string(),
        }];

        write_starter_config_with_tools(&path, 1000, &tools, false)
            .expect("first write should succeed");

        let result = write_starter_config_with_tools(&path, 1000, &tools, false);

        assert!(result.is_err());
    }

    #[test]
    fn write_starter_config_overwrites_with_force() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let path = dir.path().join("config.toml");

        std::fs::write(&path, "old contents").expect("old config should be written");

        let tools = [DetectedTool {
            rule_name: "Allow SSH client".to_string(),
            exe: PathBuf::from("/usr/bin/ssh"),
            path_group: "ssh".to_string(),
        }];

        write_starter_config_with_tools(&path, 1000, &tools, true)
            .expect("force write should succeed");

        let contents = std::fs::read_to_string(&path).expect("config should be readable");

        assert!(contents.contains("mode = \"learn\""));
        assert!(!contents.contains("old contents"));
    }

    #[test]
    fn starter_config_allows_no_detected_tools() {
        let tools = [];

        let toml = starter_config_toml_with_tools(1000, &tools);

        let config: crate::config::Config =
            toml::from_str(&toml).expect("starter config should parse");

        assert_eq!(config.allow_rules.len(), 0);
        assert!(toml.contains("groups = [\"aws\", \"ssh\", \"github\", \"gcloud\", \"docker\"]"));
    }

    #[test]
    fn detected_tools_from_statuses_returns_only_found_tools() {
        let statuses = [
            SetupToolDetection {
                tool: SetupTool {
                    command: "aws",
                    rule_name: "Allow AWS CLI",
                    path_group: "aws",
                },
                exe: Some(PathBuf::from("/usr/bin/aws")),
            },
            SetupToolDetection {
                tool: SetupTool {
                    command: "gcloud",
                    rule_name: "Allow Google Cloud CLI",
                    path_group: "gcloud",
                },
                exe: None,
            },
        ];

        let tools = detected_tools_from_statuses(&statuses);

        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].rule_name, "Allow AWS CLI");
        assert_eq!(tools[0].exe, PathBuf::from("/usr/bin/aws"));
        assert_eq!(tools[0].path_group, "aws");
    }

    #[test]
    fn setup_output_from_statuses_splits_detected_and_skipped_tools() {
        let statuses = [
            SetupToolDetection {
                tool: SetupTool {
                    command: "ssh",
                    rule_name: "Allow SSH client",
                    path_group: "ssh",
                },
                exe: Some(PathBuf::from("/usr/bin/ssh")),
            },
            SetupToolDetection {
                tool: SetupTool {
                    command: "gcloud",
                    rule_name: "Allow Google Cloud CLI",
                    path_group: "gcloud",
                },
                exe: None,
            },
        ];

        let output = setup_output_from_statuses(
            PathBuf::from("./generated-config.toml"),
            1000,
            true,
            &statuses,
        );

        assert_eq!(output.uid, 1000);
        assert!(output.written);
        assert_eq!(output.detected_tools.len(), 1);
        assert_eq!(output.skipped_tools.len(), 1);
        assert_eq!(output.detected_tools[0].command, "ssh");
        assert_eq!(output.detected_tools[0].exe, PathBuf::from("/usr/bin/ssh"));
        assert_eq!(output.skipped_tools[0].command, "gcloud");
        assert_eq!(output.skipped_tools[0].reason, "not found in PATH");
    }

    #[test]
    fn setup_output_to_json_outputs_expected_shape() {
        let statuses = [SetupToolDetection {
            tool: SetupTool {
                command: "ssh",
                rule_name: "Allow SSH client",
                path_group: "ssh",
            },
            exe: Some(PathBuf::from("/usr/bin/ssh")),
        }];

        let output = setup_output_from_statuses(
            PathBuf::from("./generated-config.toml"),
            1000,
            true,
            &statuses,
        );

        let json = setup_output_to_json(&output).expect("setup output should serialize");

        assert!(json.contains("\"output\": \"./generated-config.toml\""));
        assert!(json.contains("\"uid\": 1000"));
        assert!(json.contains("\"written\": true"));
        assert!(json.contains("\"detected_tools\""));
        assert!(json.contains("\"command\": \"ssh\""));
    }
}
