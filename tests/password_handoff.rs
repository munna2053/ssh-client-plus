#![cfg(windows)]

use sentinel_ssh::windows::{askpass::CredentialBroker, crypto::Secret};
use std::{
    os::windows::process::CommandExt,
    path::Path,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

fn helper(broker: &CredentialBroker, prompt: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sentinel-ssh"));
    command
        .arg(prompt)
        .envs(broker.environment())
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn finish(mut child: Child, broker: &mut CredentialBroker) -> Output {
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    if child.try_wait().unwrap().is_none() {
        broker.cancel();
        let _ = child.kill();
        panic!("Credential helper did not finish within five seconds.");
    }
    child.wait_with_output().unwrap()
}

#[test]
fn executable_helper_delivers_one_password_and_rejects_reuse() {
    let fixture = "  disposable পাসওয়ার্ড $(id) \\\" secret  ";
    let mut broker = CredentialBroker::new(
        Secret(fixture.as_bytes().to_vec()),
        Path::new(env!("CARGO_BIN_EXE_sentinel-ssh")),
    )
    .unwrap();
    broker.authorize_parent(std::process::id());
    assert!(
        broker
            .environment()
            .iter()
            .all(|(_, value)| !value.to_string_lossy().contains(fixture))
    );
    let child = helper(&broker, "deploy@example.com's password: ")
        .spawn()
        .unwrap();
    let output = finish(child, &mut broker);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout, format!("{fixture}\n").as_bytes());
    broker.cancel();
    let child = helper(&broker, "deploy@example.com's password: ")
        .spawn()
        .unwrap();
    let reused = finish(child, &mut broker);
    assert!(!reused.status.success());
    assert!(reused.stdout.is_empty());
}

#[test]
fn cancelled_wrong_parent_wrong_owner_and_unsupported_prompts_never_receive_passwords() {
    for case in 0..4 {
        let mut broker = CredentialBroker::new(
            Secret(b"disposable rejection fixture".to_vec()),
            Path::new(env!("CARGO_BIN_EXE_sentinel-ssh")),
        )
        .unwrap();
        broker.authorize_parent(if case == 1 {
            u32::MAX
        } else {
            std::process::id()
        });
        if case == 0 {
            broker.cancel();
        }
        let mut command = helper(
            &broker,
            if case == 3 {
                "Enter passphrase for key '/test': "
            } else {
                "deploy@example.com's password: "
            },
        );
        if case == 2 {
            command.env("SENTINEL_ASKPASS_OWNER", u32::MAX.to_string());
        }
        let child = command.spawn().unwrap();
        if case == 1 {
            thread::sleep(Duration::from_millis(100));
            broker.cancel();
        }
        let output = finish(child, &mut broker);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn maximum_supported_password_is_delivered_without_truncation() {
    let fixture = vec![b'x'; sentinel_ssh::core::MAX_SSH_PASSWORD_BYTES];
    let mut broker = CredentialBroker::new(
        Secret(fixture.clone()),
        Path::new(env!("CARGO_BIN_EXE_sentinel-ssh")),
    )
    .unwrap();
    broker.authorize_parent(std::process::id());
    let child = helper(&broker, "deploy@example.com's password: ")
        .spawn()
        .unwrap();
    let output = finish(child, &mut broker);
    assert!(output.status.success());
    assert_eq!(output.stdout.len(), fixture.len() + 1);
    assert_eq!(&output.stdout[..fixture.len()], &fixture);
    assert_eq!(output.stdout.last(), Some(&b'\n'));
}
