use crate::config::{AllowRule, Config, Mode};
use crate::event::AccessEvent;
use serde::Serialize;

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
            reason: format!(
                "matched allow rule '{}' for protected group '{matched_group}'",
                rule.name
            ),
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
            if path_matches_protected_path(&event.target_path, protected_path) {
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

    if rule.path_group != matched_group {
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
    target_path.starts_with(protected_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AllowRule, Config, Mode, ProtectedPathGroup, ProtectedUser};
    use crate::event::Operation;
    use crate::process::ProcessChainEntry;
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
                path_group: "aws".to_string(),
                parent_exe: None,
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
            operation: Operation::OpenRead,
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
}
