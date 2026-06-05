use crate::config::{AllowRule, Config, Mode};
use crate::event::{AccessEvent, FileIdentity};
use crate::identity;
use serde::Serialize;
use std::os::unix::fs::MetadataExt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "decision", rename_all = "lowercase")]
pub enum Decision {
    Allow {
        reason: String,

        #[serde(skip_serializing_if = "Option::is_none")]
        matched_path_group: Option<String>,

        #[serde(default)]
        would_deny: bool,
    },
    Deny {
        reason: String,

        #[serde(skip_serializing_if = "Option::is_none")]
        matched_path_group: Option<String>,

        #[serde(default)]
        would_deny: bool,
    },
}

pub fn decide(config: &Config, event: &AccessEvent) -> Decision {
    let Some(matched_group) = find_matching_protected_group(config, event) else {
        return Decision::Allow {
            reason: "target path is not protected".to_string(),
            matched_path_group: None,
            would_deny: false,
        };
    };

    let matched_rule = config
        .allow_rules
        .iter()
        .find(|rule| allow_rule_matches(rule, event, &matched_group));

    if let Some(rule) = matched_rule {
        return Decision::Allow {
            reason: allow_rule_match_reason(rule, &matched_group),
            matched_path_group: Some(matched_group),
            would_deny: false,
        };
    };

    match config.mode {
        Mode::Learn => Decision::Allow {
            reason: format!("learn mode: would deny access to protected group '{matched_group}'"),
            matched_path_group: Some(matched_group),
            would_deny: true,
        },
        Mode::Enforce => Decision::Deny {
            reason: format!(
                "enforce mode: no allow rule matched protected group '{matched_group}'"
            ),
            matched_path_group: Some(matched_group),
            would_deny: false,
        },
    }
}

fn allow_rule_match_reason(rule: &AllowRule, matched_group: &str) -> String {
    let identity = if rule.exe_sha256.is_some() {
        " with matching exe_sha256"
    } else {
        ""
    };

    format!(
        "matched allow rule '{}' for protected group '{matched_group}'{identity}",
        rule.name
    )
}

fn find_matching_protected_group(config: &Config, event: &AccessEvent) -> Option<String> {
    let protected_user = config.users.iter().find(|user| user.uid == event.uid)?;

    for group_name in &protected_user.groups {
        let Some(group) = config
            .protected_groups
            .iter()
            .find(|group| &group.name == group_name)
        else {
            continue;
        };

        for protected_path in &group.paths {
            if path_matches_protected_path(&event.target_path, protected_path)
                || identity_matches_protected_path(event.target_file_identity, protected_path)
            {
                return Some(group.name.clone());
            }
        }
    }

    None
}

fn allow_rule_matches(rule: &AllowRule, event: &AccessEvent, matched_group: &str) -> bool {
    if rule.uid != event.uid {
        return false;
    }

    if rule.exe != event.exe {
        return false;
    }

    if let Some(expected_hash) = &rule.exe_sha256 {
        let Ok(actual_hash) = identity::file_sha256(&event.exe) else {
            return false;
        };

        if !actual_hash.eq_ignore_ascii_case(expected_hash) {
            return false;
        }
    }

    if rule.path_group != matched_group {
        return false;
    }

    if let Some(operation) = rule.operation
        && operation != event.operation
    {
        return false;
    }

    if let Some(parent_exe) = &rule.parent_exe {
        return event
            .parent_chain
            .iter()
            .any(|parent| parent.exe.as_ref().is_some_and(|exe| exe == parent_exe));
    }

    true
}

fn path_matches_protected_path(
    target_path: &std::path::Path,
    protected_path: &std::path::Path,
) -> bool {
    if protected_path.is_relative() {
        return target_path.file_name() == protected_path.file_name();
    }

    target_path.starts_with(protected_path)
}

fn identity_matches_protected_path(
    target_identity: Option<FileIdentity>,
    protected_path: &std::path::Path,
) -> bool {
    let Some(target_identity) = target_identity else {
        return false;
    };

    if protected_path.is_relative() {
        return false;
    }

    identity_matches_existing_path(target_identity, protected_path).unwrap_or(false)
}

fn identity_matches_existing_path(
    target_identity: FileIdentity,
    protected_path: &std::path::Path,
) -> std::io::Result<bool> {
    let metadata = std::fs::symlink_metadata(protected_path)?;
    let identity = FileIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
    };

    if identity == target_identity {
        return Ok(true);
    }

    if !metadata.is_dir() {
        return Ok(false);
    }

    identity_matches_descendant(target_identity, protected_path)
}

fn identity_matches_descendant(
    target_identity: FileIdentity,
    directory: &std::path::Path,
) -> std::io::Result<bool> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        let identity = FileIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        };

        if identity == target_identity {
            return Ok(true);
        }

        if metadata.is_dir() && identity_matches_descendant(target_identity, &path)? {
            return Ok(true);
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AllowRule, Config, Mode, ProtectedPathGroup, ProtectedUser};
    use crate::event::Operation;
    use crate::process::ProcessChainEntry;
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;

    fn parent_entry(exe: &str) -> ProcessChainEntry {
        ProcessChainEntry {
            pid: 2000,
            ppid: Some(1000),
            uid: 1000,
            exe: Some(PathBuf::from(exe)),
            cmdline: Vec::new(),
        }
    }

    fn sample_config(mode: Mode) -> Config {
        Config {
            mode,
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

    fn access_event(exe: &str, target_path: &str) -> AccessEvent {
        AccessEvent {
            pid: None,
            uid: 1000,
            exe: PathBuf::from(exe),
            cwd: None,
            cmdline: Vec::new(),
            parent_chain: Vec::new(),
            target_path: PathBuf::from(target_path),
            target_file_identity: None,
            operation: Operation::OpenRead,
        }
    }

    fn file_identity(path: &std::path::Path) -> FileIdentity {
        let metadata = std::fs::metadata(path).expect("metadata should be readable");

        FileIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    }

    #[test]
    fn allow_unprotected_file() {
        let config = sample_config(Mode::Enforce);

        let event = access_event("/usr/bin/python3", "/home/alice/projects/app/main.py");

        let decision = decide(&config, &event);

        assert!(matches!(decision, Decision::Allow { .. }))
    }

    #[test]
    fn allows_matching_rule_in_enforce_mode() {
        let config = sample_config(Mode::Enforce);

        let event = access_event("/usr/bin/aws", "/home/alice/.aws/credentials");

        let decision = decide(&config, &event);

        assert!(matches!(decision, Decision::Allow { .. }))
    }

    #[test]
    fn denies_unknown_executable_in_enforce_mode() {
        let config = sample_config(Mode::Enforce);

        let event = access_event("/usr/bin/python3", "/home/alice/.aws/credentials");

        let decision = decide(&config, &event);

        assert!(matches!(decision, Decision::Deny { .. }))
    }

    #[test]
    fn allows_unknown_executable_in_learn_mode() {
        let config = sample_config(Mode::Learn);

        let event = access_event("/usr/bin/python3", "/home/alice/.aws/credentials");

        let decision = decide(&config, &event);

        assert!(matches!(decision, Decision::Allow { .. }));
    }

    #[test]
    fn allows_rule_when_parent_exe_matches() {
        let mut config = sample_config(Mode::Enforce);

        config.allow_rules[0].parent_exe = Some(PathBuf::from("/usr/bin/zsh"));

        let mut event = access_event("/usr/bin/aws", "/home/alice/.aws/credentials");

        event.parent_chain = vec![parent_entry("/usr/bin/zsh")];

        let decision = decide(&config, &event);

        assert!(matches!(decision, Decision::Allow { .. }));
    }

    #[test]
    fn denies_rule_when_parent_exe_does_not_match() {
        let mut config = sample_config(Mode::Enforce);

        config.allow_rules[0].parent_exe = Some(PathBuf::from("/usr/bin/zsh"));

        let mut event = access_event("/usr/bin/aws", "/home/alice/.aws/credentials");

        event.parent_chain = vec![parent_entry("/usr/bin/code")];

        let decision = decide(&config, &event);

        assert!(matches!(decision, Decision::Deny { .. }));
    }

    #[test]
    fn denies_rule_when_parent_exe_required_but_chain_is_empty() {
        let mut config = sample_config(Mode::Enforce);

        config.allow_rules[0].parent_exe = Some(PathBuf::from("/usr/bin/zsh"));

        let event = access_event("/usr/bin/aws", "/home/alice/.aws/credentials");

        let decision = decide(&config, &event);

        assert!(matches!(decision, Decision::Deny { .. }));
    }

    #[test]
    fn protects_file_inside_protected_directory() {
        let config = sample_config(Mode::Enforce);

        let event = access_event("/usr/bin/python3", "/home/alice/.aws/credentials");

        let decision = decide(&config, &event);

        assert!(matches!(decision, Decision::Deny { .. }));
    }

    #[test]
    fn protects_exact_protected_directory_path() {
        let config = sample_config(Mode::Enforce);

        let event = access_event("/usr/bin/python3", "/home/alice/.aws");

        let decision = decide(&config, &event);

        assert!(matches!(decision, Decision::Deny { .. }));
    }

    #[test]
    fn does_not_protect_similar_prefix_directory() {
        let config = sample_config(Mode::Enforce);

        let event = access_event("/usr/bin/python3", "/home/alice/.aws-old/credentials");

        let decision = decide(&config, &event);

        assert!(matches!(decision, Decision::Allow { .. }));
    }

    #[test]
    fn does_not_protect_similar_prefix_file_or_directory_name() {
        let config = sample_config(Mode::Enforce);

        let event = access_event("/usr/bin/python3", "/home/alice/.aws2/credentials");

        let decision = decide(&config, &event);

        assert!(matches!(decision, Decision::Allow { .. }));
    }

    #[test]
    fn allows_rule_when_operation_matches() {
        let mut config = sample_config(Mode::Enforce);

        config.allow_rules[0].operation = Some(Operation::OpenRead);

        let event = access_event("/usr/bin/aws", "/home/alice/.aws/credentials");

        let decision = decide(&config, &event);

        assert!(matches!(decision, Decision::Allow { .. }));
    }

    #[test]
    fn allows_rule_when_exe_sha256_matches() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let exe = dir.path().join("aws");
        std::fs::write(&exe, "aws cli").expect("exe should be written");
        let hash = crate::identity::file_sha256(&exe).expect("exe should hash");

        let mut config = sample_config(Mode::Enforce);
        config.allow_rules[0].exe = exe.clone();
        config.allow_rules[0].exe_sha256 = Some(hash);

        let event = access_event(
            exe.to_str().expect("path should be utf8"),
            "/home/alice/.aws/credentials",
        );

        let decision = decide(&config, &event);

        assert!(matches!(
            decision,
            Decision::Allow { reason, .. } if reason.contains("matching exe_sha256")
        ));
    }

    #[test]
    fn denies_rule_when_exe_sha256_does_not_match() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let exe = dir.path().join("aws");
        std::fs::write(&exe, "aws cli").expect("exe should be written");

        let mut config = sample_config(Mode::Enforce);
        config.allow_rules[0].exe = exe.clone();
        config.allow_rules[0].exe_sha256 =
            Some("0000000000000000000000000000000000000000000000000000000000000000".to_string());

        let event = access_event(
            exe.to_str().expect("path should be utf8"),
            "/home/alice/.aws/credentials",
        );

        let decision = decide(&config, &event);

        assert!(matches!(decision, Decision::Deny { .. }));
    }

    #[test]
    fn protects_relative_dotenv_file_name_in_project_roots() {
        let mut config = Config {
            mode: Mode::Enforce,
            users: vec![ProtectedUser {
                uid: 1000,
                groups: vec!["dotenv".to_string()],
            }],
            protected_groups: vec![ProtectedPathGroup {
                name: "dotenv".to_string(),
                paths: vec![PathBuf::from(".env")],
            }],
            allow_rules: Vec::new(),
        };

        let event = access_event("/usr/bin/python3", "/home/alice/project/.env");

        let decision = decide(&config, &event);

        assert!(matches!(decision, Decision::Deny { .. }));

        config.protected_groups[0].paths = vec![PathBuf::from(".env.local")];
        let event = access_event("/usr/bin/python3", "/home/alice/project/.env");

        let decision = decide(&config, &event);

        assert!(matches!(decision, Decision::Allow { .. }));
    }

    #[test]
    fn protects_replaced_file_inside_protected_directory() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let protected_dir = dir.path().join("protected");
        let target = protected_dir.join("secret");

        std::fs::create_dir(&protected_dir).expect("protected dir should be created");
        std::fs::write(&target, "old").expect("target should be written");
        std::fs::remove_file(&target).expect("target should be removed");
        std::fs::write(&target, "new").expect("target should be replaced");

        let config = Config {
            mode: Mode::Enforce,
            users: vec![ProtectedUser {
                uid: 1000,
                groups: vec!["test".to_string()],
            }],
            protected_groups: vec![ProtectedPathGroup {
                name: "test".to_string(),
                paths: vec![protected_dir],
            }],
            allow_rules: Vec::new(),
        };
        let event = access_event("/usr/bin/python3", target.to_str().unwrap());

        let decision = decide(&config, &event);

        assert!(matches!(decision, Decision::Deny { .. }));
    }

    #[test]
    fn protects_hard_link_outside_protected_directory_when_identity_is_available() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let protected_dir = dir.path().join("protected");
        let protected_file = protected_dir.join("secret");
        let hard_link = dir.path().join("outside-secret");

        std::fs::create_dir(&protected_dir).expect("protected dir should be created");
        std::fs::write(&protected_file, "secret").expect("protected file should be written");
        std::fs::hard_link(&protected_file, &hard_link).expect("hard link should be created");

        let config = Config {
            mode: Mode::Enforce,
            users: vec![ProtectedUser {
                uid: 1000,
                groups: vec!["test".to_string()],
            }],
            protected_groups: vec![ProtectedPathGroup {
                name: "test".to_string(),
                paths: vec![protected_dir],
            }],
            allow_rules: Vec::new(),
        };
        let mut event = access_event("/usr/bin/python3", hard_link.to_str().unwrap());
        event.target_file_identity = Some(file_identity(&hard_link));

        let decision = decide(&config, &event);

        assert!(matches!(decision, Decision::Deny { .. }));
    }

    #[test]
    fn hard_link_outside_protected_directory_still_needs_identity_to_match() {
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let protected_dir = dir.path().join("protected");
        let protected_file = protected_dir.join("secret");
        let hard_link = dir.path().join("outside-secret");

        std::fs::create_dir(&protected_dir).expect("protected dir should be created");
        std::fs::write(&protected_file, "secret").expect("protected file should be written");
        std::fs::hard_link(&protected_file, &hard_link).expect("hard link should be created");

        let config = Config {
            mode: Mode::Enforce,
            users: vec![ProtectedUser {
                uid: 1000,
                groups: vec!["test".to_string()],
            }],
            protected_groups: vec![ProtectedPathGroup {
                name: "test".to_string(),
                paths: vec![protected_dir],
            }],
            allow_rules: Vec::new(),
        };
        let event = access_event("/usr/bin/python3", hard_link.to_str().unwrap());

        let decision = decide(&config, &event);

        assert!(matches!(decision, Decision::Allow { .. }));
    }
}
