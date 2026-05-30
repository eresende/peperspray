use crate::config::{Config, Mode};
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

    let matched_rule = config.allow_rules.iter().find(|rule| {
        rule.uid == event.uid && rule.exe == event.exe && rule.path_group == matched_group
    });

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
            if event.target_path.starts_with(protected_path) {
                return Some(group.name.clone());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AllowRule, Config, Mode, ProtectedPathGroup, ProtectedUser};
    use crate::event::Operation;
    use std::path::PathBuf;

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
            }],
        }
    }

    fn access_event(exe: &str, target_path: &str) -> AccessEvent {
        AccessEvent {
            uid: 1000,
            exe: PathBuf::from(exe),
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
}
