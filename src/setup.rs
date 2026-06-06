use crate::event::Operation;
use crate::paths;
use anyhow::Context;
use serde::Serialize;
use std::collections::HashSet;
use std::io::{self, Write};
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

#[derive(Debug, Clone, Copy, Serialize)]
pub struct ProtectedPreset {
    name: &'static str,
    paths: &'static [&'static str],
    patterns: &'static [&'static str],
}

#[derive(Debug, Serialize)]
pub struct PresetsOutput {
    schema_version: u32,
    platform: &'static str,
    default_profile: &'static str,
    protected_groups: &'static [ProtectedPreset],
}

const PROTECTED_PRESETS: &[ProtectedPreset] = &[
    ProtectedPreset {
        name: "aws",
        paths: &["~/.aws"],
        patterns: &[],
    },
    ProtectedPreset {
        name: "ssh",
        paths: &["~/.ssh"],
        patterns: &[],
    },
    ProtectedPreset {
        name: "github",
        paths: &["~/.config/gh"],
        patterns: &[],
    },
    ProtectedPreset {
        name: "gcloud",
        paths: &["~/.config/gcloud"],
        patterns: &[],
    },
    ProtectedPreset {
        name: "azure",
        paths: &["~/.azure"],
        patterns: &[],
    },
    ProtectedPreset {
        name: "kubernetes",
        paths: &["~/.kube"],
        patterns: &[],
    },
    ProtectedPreset {
        name: "vault",
        paths: &["~/.vault-token"],
        patterns: &[],
    },
    ProtectedPreset {
        name: "iac",
        paths: &["~/.terraform.d", "~/.pulumi"],
        patterns: &[],
    },
    ProtectedPreset {
        name: "docker",
        paths: &["~/.docker"],
        patterns: &[],
    },
    ProtectedPreset {
        name: "npm",
        paths: &["~/.npmrc"],
        patterns: &[],
    },
    ProtectedPreset {
        name: "python",
        paths: &["~/.pypirc", "~/.config/pip/pip.conf"],
        patterns: &[],
    },
    ProtectedPreset {
        name: "java",
        paths: &["~/.m2/settings.xml", "~/.gradle/gradle.properties"],
        patterns: &[],
    },
    ProtectedPreset {
        name: "rust",
        paths: &["~/.cargo/credentials", "~/.cargo/credentials.toml"],
        patterns: &[],
    },
    ProtectedPreset {
        name: "huggingface",
        paths: &["~/.cache/huggingface/token"],
        patterns: &[],
    },
    ProtectedPreset {
        name: "ansible",
        paths: &["~/.ansible", "~/.ansible/vault_password"],
        patterns: &[],
    },
    ProtectedPreset {
        name: "git",
        paths: &["~/.git-credentials", "~/.netrc", "~/.gitconfig"],
        patterns: &[],
    },
    ProtectedPreset {
        name: "shell",
        paths: &[
            "~/.bash_history",
            "~/.zsh_history",
            "~/.config/fish/fish_history",
        ],
        patterns: &[],
    },
    ProtectedPreset {
        name: "dotenv",
        paths: &[".env", ".env.local", ".env.development", ".env.production"],
        patterns: &[],
    },
    ProtectedPreset {
        name: "browser",
        paths: &[],
        patterns: &[
            "~/.config/google-chrome/*/Cookies",
            "~/.config/google-chrome/*/Login Data",
            "~/.config/google-chrome/Local State",
            "~/.config/chromium/*/Cookies",
            "~/.config/chromium/*/Login Data",
            "~/.mozilla/firefox/*.default*/cookies.sqlite",
            "~/.mozilla/firefox/*.default*/logins.json",
            "~/.mozilla/firefox/*.default*/key4.db",
        ],
    },
    ProtectedPreset {
        name: "wallet",
        paths: &[
            "~/.electrum",
            "~/.bitcoin",
            "~/.bitmonero",
            "~/.config/Exodus",
            "~/.config/Electrum",
            "~/.config/atomic",
            "~/.config/Ledger Live",
            "~/.config/Trezor Suite",
            "~/.config/solana",
        ],
        patterns: &[],
    },
    ProtectedPreset {
        name: "password-manager",
        paths: &[
            "~/.password-store",
            "~/.gnupg",
            "~/.config/Bitwarden",
            "~/.config/keepassxc",
            "~/.config/1Password",
        ],
        patterns: &[],
    },
];

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
        command: "az",
        rule_name: "Allow Azure CLI",
        path_group: "azure",
    },
    SetupTool {
        command: "kubectl",
        rule_name: "Allow kubectl",
        path_group: "kubernetes",
    },
    SetupTool {
        command: "vault",
        rule_name: "Allow Vault CLI",
        path_group: "vault",
    },
    SetupTool {
        command: "terraform",
        rule_name: "Allow Terraform",
        path_group: "iac",
    },
    SetupTool {
        command: "pulumi",
        rule_name: "Allow Pulumi",
        path_group: "iac",
    },
    SetupTool {
        command: "docker",
        rule_name: "Allow Docker CLI",
        path_group: "docker",
    },
    SetupTool {
        command: "npm",
        rule_name: "Allow npm",
        path_group: "npm",
    },
    SetupTool {
        command: "pip",
        rule_name: "Allow pip",
        path_group: "python",
    },
    SetupTool {
        command: "cargo",
        rule_name: "Allow Cargo",
        path_group: "rust",
    },
    SetupTool {
        command: "mvn",
        rule_name: "Allow Maven",
        path_group: "java",
    },
    SetupTool {
        command: "gradle",
        rule_name: "Allow Gradle",
        path_group: "java",
    },
    SetupTool {
        command: "ansible-vault",
        rule_name: "Allow Ansible Vault",
        path_group: "ansible",
    },
    SetupTool {
        command: "git",
        rule_name: "Allow Git",
        path_group: "git",
    },
    SetupTool {
        command: "google-chrome",
        rule_name: "Allow Google Chrome",
        path_group: "browser",
    },
    SetupTool {
        command: "chromium",
        rule_name: "Allow Chromium",
        path_group: "browser",
    },
    SetupTool {
        command: "firefox",
        rule_name: "Allow Firefox",
        path_group: "browser",
    },
    SetupTool {
        command: "gpg",
        rule_name: "Allow GnuPG",
        path_group: "password-manager",
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedTool {
    command: String,
    rule_name: String,
    exe: PathBuf,
    path_group: String,
}

#[derive(Debug, Clone)]
pub struct SetupToolDetection {
    tool: SetupTool,
    exe: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct SetupOptions {
    group_names: HashSet<String>,
    allowed_commands: HashSet<String>,
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
                command: status.tool.command.to_string(),
                rule_name: status.tool.rule_name.to_string(),
                exe,
                path_group: status.tool.path_group.to_string(),
            })
        })
        .collect()
}

pub fn starter_config_toml_with_tools(uid: u32, tools: &[DetectedTool]) -> String {
    let group_names = default_group_names();
    starter_config_toml_with_selected_groups(uid, tools, &group_names)
}

pub fn starter_config_toml_with_selected_groups(
    uid: u32,
    tools: &[DetectedTool],
    group_names: &[String],
) -> String {
    let protected_groups = starter_protected_groups_toml(group_names);
    let allow_rules = starter_allow_rules_toml(uid, tools, group_names);
    let group_list = quoted_group_list(group_names);

    let mut toml = format!(
        r#"mode = "learn"

[[users]]
uid = {uid}
groups = [{group_list}]

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

fn default_group_names() -> Vec<String> {
    PROTECTED_PRESETS
        .iter()
        .map(|preset| preset.name.to_string())
        .collect()
}

fn starter_protected_groups_toml(group_names: &[String]) -> String {
    PROTECTED_PRESETS
        .iter()
        .filter(|preset| group_names.iter().any(|name| name == preset.name))
        .map(|preset| {
            let mut toml = format!(
                "[[protected_groups]]\nname = \"{}\"\npaths = [{}]",
                preset.name,
                quoted_list(preset.paths.iter().copied())
            );

            if !preset.patterns.is_empty() {
                toml.push_str(&format!(
                    "\npatterns = [{}]",
                    quoted_list(preset.patterns.iter().copied())
                ));
            }

            toml
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}

pub fn presets_output() -> PresetsOutput {
    PresetsOutput {
        schema_version: 2,
        platform: std::env::consts::OS,
        default_profile: "dev-browser-wallet",
        protected_groups: PROTECTED_PRESETS,
    }
}

pub fn print_presets(json: bool) -> anyhow::Result<()> {
    let output = presets_output();

    if json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Default profile: {}", output.default_profile);
        println!("Platform: {}", output.platform);
        println!();
        for preset in output.protected_groups {
            println!("{}", preset.name);
            for path in preset.paths {
                println!("  path: {path}");
            }
            for pattern in preset.patterns {
                println!("  pattern: {pattern}");
            }
        }
    }

    Ok(())
}

fn starter_allow_rules_toml(uid: u32, tools: &[DetectedTool], group_names: &[String]) -> String {
    tools
        .iter()
        .filter(|tool| group_names.iter().any(|name| name == &tool.path_group))
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

fn quoted_group_list(group_names: &[String]) -> String {
    quoted_list(group_names.iter().map(String::as_str))
}

fn quoted_list<'a>(values: impl Iterator<Item = &'a str>) -> String {
    values
        .map(|value| format!("\"{value}\""))
        .collect::<Vec<_>>()
        .join(", ")
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

pub fn write_starter_config_with_options(
    path: &Path,
    uid: u32,
    tools: &[DetectedTool],
    options: &SetupOptions,
    force: bool,
) -> anyhow::Result<()> {
    if path.exists() && !force {
        anyhow::bail!(
            "{} already exists; use --force to overwrite it",
            path.display()
        );
    }

    let group_names = selected_group_names(options);
    let tools = selected_tools(tools, options);

    std::fs::write(
        path,
        starter_config_toml_with_selected_groups(uid, &tools, &group_names),
    )?;

    Ok(())
}

pub fn prompt_setup_options(statuses: &[SetupToolDetection]) -> anyhow::Result<SetupOptions> {
    let mut group_names = HashSet::new();
    let mut allowed_commands = HashSet::new();

    println!("Select protected credential groups:");
    for preset in PROTECTED_PRESETS {
        if prompt_yes_no(&format!("Protect {} credentials?", preset.name), true)? {
            group_names.insert(preset.name.to_string());
        }
    }

    println!();
    println!("Select allow rules for detected tools:");
    for status in statuses.iter().filter(|status| status.exe.is_some()) {
        if !group_names.contains(status.tool.path_group) {
            continue;
        }

        if prompt_yes_no(
            &format!(
                "Allow {} to access {} credentials?",
                status.tool.command, status.tool.path_group
            ),
            true,
        )? {
            allowed_commands.insert(status.tool.command.to_string());
        }
    }

    Ok(SetupOptions {
        group_names,
        allowed_commands,
    })
}

fn selected_group_names(options: &SetupOptions) -> Vec<String> {
    PROTECTED_PRESETS
        .iter()
        .filter(|preset| options.group_names.contains(preset.name))
        .map(|preset| preset.name.to_string())
        .collect()
}

fn selected_tools(tools: &[DetectedTool], options: &SetupOptions) -> Vec<DetectedTool> {
    tools
        .iter()
        .filter(|tool| {
            options.group_names.contains(&tool.path_group)
                && options.allowed_commands.contains(&tool.command)
        })
        .cloned()
        .collect()
}

fn prompt_yes_no(prompt: &str, default: bool) -> anyhow::Result<bool> {
    let suffix = if default { "[Y/n]" } else { "[y/N]" };

    loop {
        print!("{prompt} {suffix} ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .with_context(|| "failed to read setup input")?;

        let input = input.trim().to_ascii_lowercase();

        match input.as_str() {
            "" => return Ok(default),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("Please answer yes or no."),
        }
    }
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
    use std::collections::HashSet;

    #[test]
    fn starter_config_contains_uid_and_default_groups() {
        let tools = [
            DetectedTool {
                command: "aws".to_string(),
                rule_name: "Allow AWS CLI".to_string(),
                exe: PathBuf::from("/usr/bin/aws"),
                path_group: "aws".to_string(),
            },
            DetectedTool {
                command: "ssh".to_string(),
                rule_name: "Allow SSH client".to_string(),
                exe: PathBuf::from("/usr/bin/ssh"),
                path_group: "ssh".to_string(),
            },
        ];

        let toml = starter_config_toml_with_tools(1000, &tools);

        assert!(toml.contains("uid = 1000"));
        assert!(toml.contains("\"browser\""));
        assert!(toml.contains("\"wallet\""));
        assert!(toml.contains("\"password-manager\""));
        assert!(toml.contains("paths = [\"~/.aws\"]"));
        assert!(toml.contains("paths = [\"~/.ssh\"]"));
        assert!(toml.contains("paths = [\"~/.npmrc\"]"));
        assert!(toml.contains("paths = [\".env\", \".env.local\""));
        assert!(toml.contains("patterns = [\"~/.config/google-chrome/*/Cookies\""));
        assert!(toml.contains("name = \"Allow AWS CLI\""));
        assert!(toml.contains("name = \"Allow SSH client\""));
        assert!(toml.contains("operation = \"open_read\""));
    }

    #[test]
    fn starter_config_parses_as_config() {
        let tools = [DetectedTool {
            command: "ssh".to_string(),
            rule_name: "Allow SSH client".to_string(),
            exe: PathBuf::from("/usr/bin/ssh"),
            path_group: "ssh".to_string(),
        }];

        let toml = starter_config_toml_with_tools(1000, &tools);

        let config: crate::config::Config =
            toml::from_str(&toml).expect("starter config should parse");

        assert_eq!(config.mode, crate::config::Mode::Learn);
        assert_eq!(config.users.len(), 1);
        assert_eq!(config.protected_groups.len(), PROTECTED_PRESETS.len());
        assert_eq!(config.allow_rules.len(), 1);
    }

    #[test]
    fn write_starter_config_writes_file() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let path = dir.path().join("config.toml");

        let tools = [DetectedTool {
            command: "ssh".to_string(),
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
            command: "ssh".to_string(),
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
            command: "ssh".to_string(),
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
        assert!(toml.contains("\"browser\""));
        assert!(toml.contains("\"wallet\""));
        assert!(toml.contains("\"password-manager\""));
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
        assert_eq!(tools[0].command, "aws");
        assert_eq!(tools[0].rule_name, "Allow AWS CLI");
        assert_eq!(tools[0].exe, PathBuf::from("/usr/bin/aws"));
        assert_eq!(tools[0].path_group, "aws");
    }

    #[test]
    fn starter_config_with_options_filters_groups_and_tools() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let path = dir.path().join("config.toml");
        let tools = [
            DetectedTool {
                command: "aws".to_string(),
                rule_name: "Allow AWS CLI".to_string(),
                exe: PathBuf::from("/usr/bin/aws"),
                path_group: "aws".to_string(),
            },
            DetectedTool {
                command: "ssh".to_string(),
                rule_name: "Allow SSH client".to_string(),
                exe: PathBuf::from("/usr/bin/ssh"),
                path_group: "ssh".to_string(),
            },
        ];
        let options = SetupOptions {
            group_names: HashSet::from(["aws".to_string()]),
            allowed_commands: HashSet::from(["aws".to_string()]),
        };

        write_starter_config_with_options(&path, 1000, &tools, &options, false)
            .expect("config should be written");

        let contents = std::fs::read_to_string(&path).expect("config should be readable");

        assert!(contents.contains("groups = [\"aws\"]"));
        assert!(contents.contains("name = \"aws\""));
        assert!(!contents.contains("name = \"ssh\""));
        assert!(contents.contains("Allow AWS CLI"));
        assert!(!contents.contains("Allow SSH client"));
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
