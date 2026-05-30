use anyhow::Context;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub uid: u32,
    pub exe: PathBuf,
    pub cwd: PathBuf,
    pub cmdline: Vec<String>,
}

#[derive(Debug, Clone)]
struct ProcessStatus {
    uid: u32,
    ppid: Option<u32>,
}

fn read_process_status(pid: u32) -> anyhow::Result<ProcessStatus> {
    let status_path = format!("/proc/{pid}/status");
    let status = fs::read_to_string(&status_path)
        .with_context(|| format!("failed to read {status_path}"))?;

    let uid = parse_uid_from_status(&status)
        .with_context(|| format!("failed to pars uid from {status_path}"))?;

    let ppid = parse_ppid_from_status(&status).ok();

    Ok(ProcessStatus { uid, ppid })
}

pub fn inspect_process(pid: u32) -> anyhow::Result<ProcessInfo> {
    let proc_dir = PathBuf::from(format!("/proc/{pid}"));

    let status = read_process_status(pid)?;
    let exe = fs::read_link(proc_dir.join("exe"))
        .with_context(|| format!("failed to read /proc/{pid}/exe"))?;
    let cwd = fs::read_link(proc_dir.join("cwd"))
        .with_context(|| format!("failed to read /proc/{pid}/cwd"))?;
    let cmdline = read_process_cmdline(pid)?;

    Ok(ProcessInfo {
        pid,
        ppid: status.ppid,
        uid: status.uid,
        exe,
        cwd,
        cmdline,
    })
}

fn read_process_cmdline(pid: u32) -> anyhow::Result<Vec<String>> {
    let cmdline_path = format!("/proc/{pid}/cmdline");
    let bytes =
        fs::read(&cmdline_path).with_context(|| format!("failed to read {cmdline_path}"))?;

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

fn parse_ppid_from_status(status: &str) -> anyhow::Result<u32> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            let ppid = rest
                .split_whitespace()
                .next()
                .context("PPid line did not contain a parent pid")?
                .parse::<u32>()
                .context("failed to parse parent pid")?;

            return Ok(ppid);
        }
    }

    anyhow::bail!("PPid line not found");
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
PPid:\t123
Uid:\t1000\t1000\t1000\t1000
Gid:\t1000\t1000\t1000\t1000
";
        let uid = parse_uid_from_status(status).expect("uid should parse");

        assert_eq!(uid, 1000);
    }

    #[test]
    fn parses_ppicd_from_status() {
        let status = "\
Name:\tbash
State:\tS (sleeping)
PPid:\t123
Uid:\t1000\t1000\t1000\t1000
";
        let ppid = parse_ppid_from_status(status).expect("ppid should parse");

        assert_eq!(ppid, 123);
    }

    #[test]
    fn parse_ppid_fails_when_missing() {
        let status = "Name:\tbash\n";

        let result = parse_ppid_from_status(status);

        assert!(result.is_err());
    }

    #[test]
    fn reads_process_status_fields() {
        let status = "\
Name:\tbash
State:\tS (sleeping)
PPid:\t123
Uid:\t1000\t1000\t1000\t1000
";

        let uid = parse_uid_from_status(status).expect("uid should parse");
        let ppid = parse_ppid_from_status(status).expect("ppid should parse");

        assert_eq!(uid, 1000);
        assert_eq!(ppid, 123);
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
