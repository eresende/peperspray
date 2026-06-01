use crate::event::Operation;
use crate::paths;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub mode: Mode,
    pub users: Vec<ProtectedUser>,
    pub protected_groups: Vec<ProtectedPathGroup>,
    pub allow_rules: Vec<AllowRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Learn,
    Enforce,
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mode::Learn => write!(f, "learn"),
            Mode::Enforce => write!(f, "enforce"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProtectedUser {
    pub uid: u32,
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProtectedPathGroup {
    pub name: String,
    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AllowRule {
    pub name: String,
    pub uid: u32,
    pub exe: PathBuf,
    pub path_group: String,

    #[serde(default)]
    pub parent_exe: Option<PathBuf>,

    #[serde(default)]
    pub operation: Option<Operation>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct AllowRuleBehaviorKey<'a> {
    uid: u32,
    exe: &'a PathBuf,
    path_group: &'a str,
    parent_exe: Option<&'a PathBuf>,
    operation: Option<Operation>,
}

pub fn load_config(path: &Path) -> anyhow::Result<Config> {
    let contents = fs::read_to_string(path)?;
    let mut config: Config = toml::from_str(&contents)?;

    normalize_config_paths(&mut config);

    Ok(config)
}

pub fn validate_config(config: &Config) -> Vec<String> {
    let mut errors: Vec<String> = Vec::new();

    validate_user_groups(config, &mut errors);
    validate_allow_rule_groups(config, &mut errors);
    validate_duplicate_group_names(config, &mut errors);
    validate_duplicate_rule_names(config, &mut errors);
    validate_duplicate_allow_rule_behavior(config, &mut errors);

    errors
}

fn validate_user_groups(config: &Config, errors: &mut Vec<String>) {
    for user in &config.users {
        for group_name in &user.groups {
            let group_exists = config
                .protected_groups
                .iter()
                .any(|group| group.name == *group_name);

            if !group_exists {
                errors.push(format!(
                    "user uid {} references unknown protected group '{}'",
                    user.uid, group_name
                ));
            }
        }
    }
}

fn validate_allow_rule_groups(config: &Config, errors: &mut Vec<String>) {
    for rule in &config.allow_rules {
        let group_exists = config
            .protected_groups
            .iter()
            .any(|group| group.name == rule.path_group);

        if !group_exists {
            errors.push(format!(
                "allow rule '{}' references unknown path group '{}'",
                rule.name, rule.path_group
            ));
        }
    }
}

fn validate_duplicate_group_names(config: &Config, errors: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();

    for group in &config.protected_groups {
        if !seen.insert(&group.name) {
            errors.push(format!("duplicate protected group name '{}'", group.name));
        }
    }
}

fn validate_duplicate_rule_names(config: &Config, errors: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();

    for rule in &config.allow_rules {
        if !seen.insert(&rule.name) {
            errors.push(format!("duplicate allow rule name '{}'", rule.name));
        }
    }
}

fn validate_duplicate_allow_rule_behavior(config: &Config, errors: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();

    for rule in &config.allow_rules {
        let key = AllowRuleBehaviorKey {
            uid: rule.uid,
            exe: &rule.exe,
            path_group: &rule.path_group,
            parent_exe: rule.parent_exe.as_ref(),
            operation: rule.operation,
        };

        if !seen.insert(key) {
            errors.push(format!(
                "duplicate allow rule behavior: uid {}, exe '{}', path_group '{}', parent_exe '{}', operation '{}'",
                rule.uid,
                rule.exe.display(),
                rule.path_group,
                rule.parent_exe
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "<none>".to_string()),
                rule.operation
                    .map(|operation| operation.to_string())
                    .unwrap_or_else(|| "<any>".to_string())
            ));
        }
    }
}

pub fn normalize_config_paths(config: &mut Config) {
    for group in &mut config.protected_groups {
        for path in &mut group.paths {
            *path = paths::expand_and_normalize_path(path);
        }
    }

    for rule in &mut config.allow_rules {
        rule.exe = paths::normalize_path(&rule.exe);

        if let Some(parent_exe) = &rule.parent_exe {
            rule.parent_exe = Some(paths::normalize_path(parent_exe));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> Config {
        Config {
            mode: Mode::Enforce,
            users: vec![ProtectedUser {
                uid: 1000,
                groups: vec!["aws".to_string()],
            }],
            protected_groups: vec![ProtectedPathGroup {
                name: "aws".to_string(),
                paths: vec![PathBuf::from("/home/alice/.aws")],
            }],
            allow_rules: vec![AllowRule {
                name: "Allow AWS CLI".to_string(),
                uid: 1000,
                exe: PathBuf::from("/usr/bin/aws"),
                path_group: "aws".to_string(),
                parent_exe: None,
                operation: None,
            }],
        }
    }

    #[test]
    fn valid_config_has_no_errors() {
        let config = sample_config();

        let errors = validate_config(&config);

        assert!(errors.is_empty());
    }

    #[test]
    fn detects_unknown_user_group() {
        let mut config = sample_config();
        config.users[0].groups = vec!["missing".to_string()];

        let errors = validate_config(&config);

        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("unknown protected group 'missing'"));
    }

    #[test]
    fn detects_unknown_allow_rule_group() {
        let mut config = sample_config();
        config.allow_rules[0].path_group = "missing".to_string();

        let errors = validate_config(&config);

        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("unknown path group 'missing'"));
    }

    #[test]
    fn detects_duplicate_group_names() {
        let mut config = sample_config();

        config.protected_groups.push(ProtectedPathGroup {
            name: "aws".to_string(),
            paths: vec![PathBuf::from("/some/other/path")],
        });

        let errors = validate_config(&config);

        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("duplicate protected group name 'aws'"));
    }

    #[test]
    fn detects_duplicate_rule_names() {
        let mut config = sample_config();

        config.allow_rules.push(AllowRule {
            name: "Allow AWS CLI".to_string(),
            uid: 1000,
            exe: PathBuf::from("/usr/local/bin/aws"),
            path_group: "aws".to_string(),
            parent_exe: None,
            operation: None,
        });

        let errors = validate_config(&config);

        assert_eq!(errors.len(), 1);
        println!("{}", errors[0]);
        assert!(errors[0].contains("duplicate allow rule name 'Allow AWS CLI'"));
    }

    #[test]
    fn detects_duplicate_allow_rule_behavior() {
        let mut config = sample_config();

        config.allow_rules.push(AllowRule {
            name: "Another AWS CLI rule".to_string(),
            uid: 1000,
            exe: PathBuf::from("/usr/bin/aws"),
            path_group: "aws".to_string(),
            parent_exe: None,
            operation: None,
        });

        let errors = validate_config(&config);

        assert_eq!(errors.len(), 1);
        assert!(
            errors[0].contains("duplicate allow rule behavior"),
            "unexpected error: {:?}",
            errors
        );
    }

    #[test]
    fn normalize_config_keeps_missing_paths() {
        let mut config = sample_config();

        config.allow_rules[0].exe = PathBuf::from("/missing/bin/aws");

        normalize_config_paths(&mut config);

        assert_eq!(
            config.protected_groups[0].paths[0],
            PathBuf::from("/home/alice/.aws")
        );
        assert_eq!(config.allow_rules[0].exe, PathBuf::from("/missing/bin/aws"));
    }

    #[test]
    fn parses_allow_rule_operation() {
        let toml = r#"
mode = "enforce"

[[users]]
uid = 1000
groups = ["aws"]

[[protected_groups]]
name = "aws"
paths = ["/home/alice/.aws"]

[[allow_rules]]
name = "Allow AWS CLI"
uid = 1000
exe = "/usr/bin/aws"
path_group = "aws"
operation = "open_read"
"#;

        let config: Config = toml::from_str(toml).expect("config should parse");

        assert_eq!(config.allow_rules[0].operation, Some(Operation::OpenRead));
    }

    #[test]
    fn mode_display_uses_lowercase_names() {
        assert_eq!(Mode::Learn.to_string(), "learn");
        assert_eq!(Mode::Enforce.to_string(), "enforce");
    }

    #[test]
    fn normalize_config_expands_tilde_in_protected_paths() {
        let Some(home) = std::env::var_os("HOME") else {
            return;
        };

        let mut config = sample_config();

        config.protected_groups[0].paths = vec![PathBuf::from("~/.aws")];

        normalize_config_paths(&mut config);

        assert_eq!(
            config.protected_groups[0].paths[0],
            PathBuf::from(home).join(".aws")
        );
    }
}
