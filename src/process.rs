use anyhow::Context;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub uid: u32,
    pub exe: PathBuf,
    pub cwd: PathBuf,
    pub cmdline: Vec<String>,
}

pub fn inspect_process(pid: u32) -> anyhow::Result<ProcessInfo> {
    let proc_dir = PathBuf::from(format!("/proc/{pid}"));

    let uid = read_process_uid(pid)?;
    let exe = fs::read_link(proc_dir.join("exe"))
        .with_context(|| format!("failed to read /proc/{pid}/exe"))?;
    let cwd = fs::read_link(proc_dir.join("cwd"))
        .with_context(|| format!("failed to read /proc/{pid}/cwd"))?;
    let cmdline = read_process_cmdline(pid)?;

    Ok(ProcessInfo {
        pid,
        uid,
        exe,
        cwd,
        cmdline,
    })
}

fn read_process_uid(pid: u32) -> anyhow::Result<u32> {
    let status_path = format!("/proc/{pid}/status");
    let status = fs::read_to_string(&status_path)
        .with_context(|| format!("failed to read {status_path}"))?;

    parse_uid_from_status(&status)
        .with_context(|| format!("failed to parse uid from {status_path}"))
}

fn read_process_cmdline(pid: u32) -> anyhow::Result<Vec<String>> {
    let cmdline_path = format!("/proc/{pid}/cmdline");
    let bytes = fs::read(&cmdline_path)
        .with_context(|| format!("failed to read {cmdline_path}"))?;

    Ok(parse_cmdline(&bytes))
}

fn parse_uid_from_status(status: &str) -> anyhow::Result<u32> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            let uid = rest
                .split_whitespace()
                .next()
                .context("Uid line did not contain a real uid")?
                .parse::<u32>()
                .context("failed to parse real uid")?;

            return Ok(uid);
        }
    }

    anyhow::bail!("Uid line not found");
}

fn parse_cmdline(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_uid_from_status() {
        let status = "
Name:\tbash
Umask:\t0022
State:\tS (sleeping)
Uid:\t1000\t1000\t1000\t1000
Gid:\t1000\t1000\t1000\t1000
";
        let uid = parse_uid_from_status(status).expect("uid should parse");

        assert_eq!(uid, 1000);
    }

    #[test]
    fn parse_uid_fails_when_missing() {
        let status = "Name:\tbash\n";

        let result = parse_uid_from_status(status);

        assert!(result.is_err());
    }

    #[test]
    fn parses_cmdline() {
        let bytes = b"/usr/bin/python3\0script.py\0--flag\0";

        let args = parse_cmdline(bytes);

        assert_eq!(
            args,
            vec![
                "/usr/bin/python3".to_string(),
                "script.py".to_string(),
                "--flag".to_string()
            ]
        );
    }

    #[test]
    fn parses_empty_cmdline() {
        let args = parse_cmdline(b"");

        assert!(args.is_empty());
    }
}

