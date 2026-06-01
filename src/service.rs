use std::process::Command;

pub const SERVICE_NAME: &str = "pepersprayd";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAction {
    Status,
    Start,
    Stop,
    Restart,
}

impl ServiceAction {
    fn systemctl_verb(self) -> &'static str {
        match self {
            ServiceAction::Status => "status",
            ServiceAction::Start => "start",
            ServiceAction::Stop => "stop",
            ServiceAction::Restart => "restart",
        }
    }
}

pub fn systemctl_args(action: ServiceAction) -> [&'static str; 2] {
    [action.systemctl_verb(), SERVICE_NAME]
}

pub fn run_systemctl(action: ServiceAction) -> anyhow::Result<()> {
    let program = std::env::var("PEPERSPRAY_SYSTEMCTL").unwrap_or_else(|_| "systemctl".to_string());
    let args = systemctl_args(action);
    let status = Command::new(&program).args(args).status()?;

    if !status.success() {
        anyhow::bail!(
            "{} {} {} exited with status {}",
            program,
            args[0],
            args[1],
            status
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemctl_args_match_service_actions() {
        assert_eq!(
            systemctl_args(ServiceAction::Status),
            ["status", "pepersprayd"]
        );
        assert_eq!(
            systemctl_args(ServiceAction::Start),
            ["start", "pepersprayd"]
        );
        assert_eq!(systemctl_args(ServiceAction::Stop), ["stop", "pepersprayd"]);
        assert_eq!(
            systemctl_args(ServiceAction::Restart),
            ["restart", "pepersprayd"]
        );
    }
}
