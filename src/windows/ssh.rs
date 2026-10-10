use super::paths::AppPaths;
use super::process::ConsoleProcess;
use crate::{
    Result,
    core::{Host, ReadOnlyAction},
};
use std::path::Path;

pub fn arguments(
    host: &Host,
    known_hosts: &Path,
    action: Option<ReadOnlyAction>,
) -> Result<Vec<String>> {
    host.validate()?;
    let trust_path = known_hosts
        .to_str()
        .ok_or("OpenSSH trust path is not Unicode.")?
        .replace('\\', "/");
    if trust_path.contains(['"', '\n', '\r', '\0']) {
        return Err("Invalid host trust file path.".into());
    }
    let mut args: Vec<String> = vec![
        "-F".into(),
        "none".into(),
        "-o".into(),
        "StrictHostKeyChecking=ask".into(),
        "-o".into(),
        format!("UserKnownHostsFile=\"{trust_path}\""),
        "-o".into(),
        "GlobalKnownHostsFile=none".into(),
        "-o".into(),
        "ForwardAgent=no".into(),
        "-o".into(),
        "ClearAllForwardings=yes".into(),
        "-o".into(),
        "PreferredAuthentications=publickey".into(),
        "-o".into(),
        "PasswordAuthentication=no".into(),
        "-o".into(),
        "KbdInteractiveAuthentication=no".into(),
        "-o".into(),
        "ConnectTimeout=15".into(),
        "-o".into(),
        "ServerAliveInterval=30".into(),
        "-p".into(),
        host.port.to_string(),
        "-l".into(),
        host.username.clone(),
    ];
    if !host.identity_path.is_empty() {
        args.extend([
            "-o".into(),
            "IdentitiesOnly=yes".into(),
            "-i".into(),
            host.identity_path.clone(),
        ]);
    }
    if action.is_some() {
        args.push("-tt".into());
    }
    args.push(host.address.clone());
    if let Some(action) = action {
        args.push(format!("{}; sentinel_status=$?; printf '\\nExit code: %s\\nPress Enter to close. ' \"$sentinel_status\"; read -r sentinel_reply; exit \"$sentinel_status\"", action.command()));
    }
    Ok(args)
}

pub fn connect(
    paths: &AppPaths,
    host: &Host,
    action: Option<ReadOnlyAction>,
) -> Result<ConsoleProcess> {
    if !paths.ssh.is_file() {
        return Err("Windows OpenSSH Client is missing. Enable OpenSSH Client in Windows Settings > Optional features, then reopen SentinelSSH.".into());
    }
    if !host.identity_path.is_empty() {
        let path = Path::new(&host.identity_path);
        if !path.is_absolute() || !path.is_file() {
            return Err("Choose an existing absolute OpenSSH identity-file path, or leave it blank to use your Windows SSH agent.".into());
        }
    }
    let args = arguments(host, &paths.known_hosts, action)?;
    super::process::spawn_console(&paths.ssh, &args, &paths.root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_separate_arguments_and_preserves_host_verification() {
        let host = Host {
            name: "Test".into(),
            address: "example.com".into(),
            port: 22,
            username: "deploy".into(),
            identity_path: "C:\\Keys with spaces\\id_ed25519".into(),
        };
        let args = arguments(
            &host,
            Path::new("C:\\Data with spaces\\known_hosts"),
            Some(ReadOnlyAction::Disk),
        )
        .unwrap();
        assert!(args.iter().any(|arg| arg == "StrictHostKeyChecking=ask"));
        assert!(args.iter().any(|arg| arg == "ForwardAgent=no"));
        assert!(args.iter().any(|arg| arg == &host.identity_path));
        assert_eq!(args[args.len() - 2], "example.com");
        assert!(
            args.last()
                .unwrap()
                .starts_with("df -h; sentinel_status=$?;")
        );
        assert!(
            !args
                .iter()
                .any(|arg| arg.contains("StrictHostKeyChecking=no"))
        );
    }
}
