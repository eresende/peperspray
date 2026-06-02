use crate::event::Operation;
use crate::identity;
use crate::paths;
use nix::unistd::{Uid, User};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub mode: Mode,
    pub users: Vec<ProtectedUser>,
    pub protected_groups: Vec<ProtectedPathGroup>,

    #[serde(default)]
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
#[serde(deny_unknown_fields)]
pub struct ProtectedUser {
    pub uid: u32,
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedPathGroup {
    pub name: String,
    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AllowRule {
    pub name: String,
    pub uid: u32,
    pub exe: PathBuf,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe_sha256: Option<String>,

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
    exe_sha256: Option<&'a String>,
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

pub fn backup_path_for_config(path: &Path) -> PathBuf {
    let mut file_name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| "config.toml".into());

    file_name.push(".bak");

    path.with_file_name(file_name)
}

pub fn set_config_mode(path: &Path, mode: Mode) -> anyhow::Result<PathBuf> {
    let contents = fs::read_to_string(path)?;
    let mut document: toml::Value = toml::from_str(&contents)?;

    document["mode"] = toml::Value::String(mode.to_string());

    let updated = toml::to_string_pretty(&document)?;
    let backup_path = backup_path_for_config(path);
    let temp_path = temp_path_for_config(path);

    fs::copy(path, &backup_path)?;
    fs::write(&temp_path, updated)?;
    fs::rename(&temp_path, path)?;

    Ok(backup_path)
}

pub fn validate_config(config: &Config) -> Vec<String> {
    let mut errors: Vec<String> = Vec::new();

    validate_user_groups(config, &mut errors);
    validate_allow_rule_groups(config, &mut errors);
    validate_duplicate_group_names(config, &mut errors);
    validate_duplicate_rule_names(config, &mut errors);
    validate_duplicate_allow_rule_behavior(config, &mut errors);
    validate_allow_rule_hashes(config, &mut errors);

    errors
}

fn temp_path_for_config(path: &Path) -> PathBuf {
    let mut file_name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| "config.toml".into());

    file_name.push(".tmp");

    path.with_file_name(file_name)
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
            exe_sha256: rule.exe_sha256.as_ref(),
            path_group: &rule.path_group,
            parent_exe: rule.parent_exe.as_ref(),
            operation: rule.operation,
        };

        if !seen.insert(key) {
            errors.push(format!(
                "duplicate allow rule behavior: uid {}, exe '{}', exe_sha256 '{}', path_group '{}', parent_exe '{}', operation '{}'",
                rule.uid,
                rule.exe.display(),
                rule.exe_sha256.as_deref().unwrap_or("<none>"),
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

fn validate_allow_rule_hashes(config: &Config, errors: &mut Vec<String>) {
    for rule in &config.allow_rules {
        if let Some(hash) = &rule.exe_sha256
            && !identity::is_sha256_hex(hash)
        {
            errors.push(format!(
                "allow rule '{}' has invalid exe_sha256 '{}'; expected 64 hex characters",
                rule.name, hash
            ));
        }
    }
}

pub fn normalize_config_paths(config: &mut Config) {
    let user_homes = user_homes_by_group(config);

    for group in &mut config.protected_groups {
        group.paths = group
            .paths
            .iter()
            .flat_map(|path| normalize_protected_path(path, &group.name, &user_homes))
            .collect();
    }

    for rule in &mut config.allow_rules {
        rule.exe = paths::normalize_path(&rule.exe);

        if let Some(parent_exe) = &rule.parent_exe {
            rule.parent_exe = Some(paths::normalize_path(parent_exe));
        }
    }
}

fn normalize_protected_path(
    path: &Path,
    group_name: &str,
    user_homes: &HashMap<String, Vec<PathBuf>>,
) -> Vec<PathBuf> {
    if !paths::is_tilde_path(path) {
        return vec![paths::expand_and_normalize_path(path)];
    }

    let Some(homes) = user_homes.get(group_name) else {
        return vec![paths::expand_and_normalize_path(path)];
    };

    let expanded = homes
        .iter()
        .map(|home| paths::normalize_path(&paths::expand_tilde_with_home(path, home)))
        .collect::<Vec<_>>();

    if expanded.is_empty() {
        vec![paths::expand_and_normalize_path(path)]
    } else {
        expanded
    }
}

fn user_homes_by_group(config: &Config) -> HashMap<String, Vec<PathBuf>> {
    let mut homes = HashMap::<String, Vec<PathBuf>>::new();

    for user in &config.users {
        let Some(home) = home_dir_for_uid(user.uid) else {
            continue;
        };

        for group_name in &user.groups {
            homes
                .entry(group_name.clone())
                .or_default()
                .push(home.clone());
        }
    }

    homes
}

fn home_dir_for_uid(uid: u32) -> Option<PathBuf> {
    User::from_uid(Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|user| user.dir)
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
                exe_sha256: None,
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
            exe_sha256: None,
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
            exe_sha256: None,
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
    fn detects_invalid_allow_rule_exe_sha256() {
        let mut config = sample_config();

        config.allow_rules[0].exe_sha256 = Some("not-a-sha256".to_string());

        let errors = validate_config(&config);

        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("invalid exe_sha256"));
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
    fn rejects_unknown_allow_rule_fields() {
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
sha256 = "not-the-right-field"
path_group = "aws"
"#;

        let result = toml::from_str::<Config>(toml);

        assert!(result.is_err());
    }

    #[test]
    fn mode_display_uses_lowercase_names() {
        assert_eq!(Mode::Learn.to_string(), "learn");
        assert_eq!(Mode::Enforce.to_string(), "enforce");
    }

    #[test]
    fn normalize_config_expands_tilde_in_protected_paths() {
        let user_homes = HashMap::from([("aws".to_string(), vec![PathBuf::from("/home/alice")])]);

        let paths = normalize_protected_path(Path::new("~/.aws"), "aws", &user_homes);

        assert_eq!(paths, vec![PathBuf::from("/home/alice/.aws")]);
    }

    #[test]
    fn backup_path_appends_bak_to_file_name() {
        assert_eq!(
            backup_path_for_config(Path::new("/tmp/config.toml")),
            PathBuf::from("/tmp/config.toml.bak")
        );
    }

    #[test]
    fn set_config_mode_updates_mode_and_writes_backup() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let path = dir.path().join("config.toml");

        std::fs::write(
            &path,
            r#"mode = "learn"

[[users]]
uid = 1000
groups = ["aws"]

[[protected_groups]]
name = "aws"
paths = ["~/.aws"]
"#,
        )
        .expect("config should be written");

        let backup_path = set_config_mode(&path, Mode::Enforce).expect("mode should be updated");
        let updated = std::fs::read_to_string(&path).expect("updated config should be readable");
        let backup = std::fs::read_to_string(&backup_path).expect("backup should be readable");

        assert!(updated.contains("mode = \"enforce\""));
        assert!(updated.contains("paths = [\"~/.aws\"]"));
        assert!(backup.contains("mode = \"learn\""));
    }
}
