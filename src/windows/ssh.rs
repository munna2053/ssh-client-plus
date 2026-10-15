use super::paths::AppPaths;
use super::pty::PtyProcess;
use super::{askpass::CredentialBroker, crypto::Secret};
use crate::{
    Result,
    core::{Authentication, Host, ReadOnlyAction},
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
    match host.authentication {
        Authentication::Key => args.extend([
            "-o".into(),
            "PreferredAuthentications=publickey".into(),
            "-o".into(),
            "PasswordAuthentication=no".into(),
        ]),
        Authentication::Password => args.extend([
            "-o".into(),
            "PreferredAuthentications=password".into(),
            "-o".into(),
            "PasswordAuthentication=yes".into(),
            "-o".into(),
            "PubkeyAuthentication=no".into(),
            "-o".into(),
            "NumberOfPasswordPrompts=1".into(),
        ]),
    }
    if host.authentication == Authentication::Key && !host.identity_path.is_empty() {
        args.extend([
            "-o".into(),
            "IdentitiesOnly=yes".into(),
            "-i".into(),
            host.identity_path.clone(),
        ]);
    }
    args.push("-tt".into());
    args.push(host.address.clone());
    if let Some(action) = action {
        args.push(format!("{}; sentinel_status=$?; printf '\\nExit code: %s\\n' \"$sentinel_status\"; exit \"$sentinel_status\"", action.command()));
    }
    Ok(args)
}

pub struct SshSession {
    process: PtyProcess,
    credential: Option<CredentialBroker>,
}

impl SshSession {
    #[cfg(test)]
    pub(crate) fn from_test_process(process: PtyProcess) -> Self {
        Self {
            process,
            credential: None,
        }
    }

    pub fn input(&self) -> std::sync::mpsc::SyncSender<Secret> {
        self.process.input()
    }
    pub fn resize(&self, columns: usize, rows: usize) -> Result<()> {
        self.process.resize(columns, rows)
    }
    pub fn output(&self) -> Vec<Vec<u8>> {
        self.process.output()
    }
    pub fn finish_output(&mut self) -> Vec<Vec<u8>> {
        self.process.finish_output()
    }
    pub fn try_wait(&self) -> Result<Option<u32>> {
        self.process.try_wait()
    }
    pub fn cancel_pending_credentials(&mut self) {
        if let Some(mut credential) = self.credential.take() {
            credential.cancel();
        }
    }
}

pub fn connect(
    paths: &AppPaths,
    host: &Host,
    action: Option<ReadOnlyAction>,
    password: Option<Secret>,
    size: (usize, usize),
) -> Result<SshSession> {
    if !paths.ssh.is_file() {
        return Err("Windows OpenSSH Client is missing. Enable OpenSSH Client in Windows Settings > Optional features, then reopen SentinelSSH.".into());
    }
    if host.authentication == Authentication::Key && !host.identity_path.is_empty() {
        let path = Path::new(&host.identity_path);
        if !path.is_absolute() || !path.is_file() {
            return Err("Choose an existing absolute OpenSSH identity-file path, or leave it blank to use your Windows SSH agent.".into());
        }
    }
    let args = arguments(host, &paths.known_hosts, action)?;
    let credential = match (host.authentication, password) {
        (Authentication::Key, None) => None,
        (Authentication::Password, Some(password)) => Some(CredentialBroker::new(
            password,
            &std::env::current_exe().map_err(|_| "Cannot locate the SSH credential helper.")?,
        )?),
        _ => {
            return Err(
                "The selected authentication method requires a matching credential.".into(),
            );
        }
    };
    let mut environment = credential
        .as_ref()
        .map_or_else(Vec::new, CredentialBroker::environment);
    environment.push(("TERM".into(), "xterm-256color".into()));
    let process = super::pty::spawn(&paths.ssh, &args, &paths.root, &environment, size.0, size.1)?;
    if let Some(broker) = &credential {
        broker.authorize_parent(process.id());
    }
    Ok(SshSession {
        process,
        credential,
    })
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
            authentication: Authentication::Key,
            password: None,
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

    #[test]
    fn saved_password_login_disables_keys_and_keeps_credentials_out_of_arguments() {
        let host = Host {
            name: "Password login".into(),
            address: "example.com".into(),
            port: 22,
            username: "deploy".into(),
            identity_path: "C:\\unused-key".into(),
            authentication: Authentication::Password,
            password: Some(crate::core::SavedPassword {
                id: [9; 16],
                ciphertext: vec![7; 48],
            }),
        };
        let args = arguments(&host, Path::new("C:\\known_hosts"), None).unwrap();
        for option in [
            "PreferredAuthentications=password",
            "PasswordAuthentication=yes",
            "PubkeyAuthentication=no",
            "KbdInteractiveAuthentication=no",
            "NumberOfPasswordPrompts=1",
            "StrictHostKeyChecking=ask",
            "ForwardAgent=no",
        ] {
            assert!(args.iter().any(|arg| arg == option));
        }
        assert!(
            !args
                .iter()
                .any(|arg| arg == "-i" || arg == &host.identity_path)
        );
    }
}
