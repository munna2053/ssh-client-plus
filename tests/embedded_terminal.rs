#![cfg(windows)]

use sentinel_ssh::{
    core::{Authentication, Host},
    terminal::Terminal,
    windows::{
        paths::{AppPaths, secure_directory},
        ssh,
    },
};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

#[test]
fn system_openssh_errors_are_received_in_the_embedded_terminal() {
    let executable = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
        .join("System32")
        .join("OpenSSH")
        .join("ssh.exe");
    if !executable.is_file() {
        eprintln!("OpenSSH Client is not installed; system executable smoke test skipped.");
        return;
    }
    // Reserve a loopback port then release it: no external host or credential is used.
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    let root = std::env::temp_dir().join(format!(
        "sentinel-pty-ssh-test-{}-{}",
        std::process::id(),
        port
    ));
    secure_directory(&root).unwrap();
    let paths = AppPaths {
        database_dir: root.join("database"),
        known_hosts: root.join("known_hosts"),
        root,
        ssh: executable,
    };
    let host = Host {
        name: "Disposable loopback fixture".into(),
        address: "127.0.0.1".into(),
        port,
        username: "sentinel_test".into(),
        identity_path: String::new(),
        authentication: Authentication::Key,
        password: None,
    };
    let mut session = ssh::connect(&paths, &host, None, None, (110, 32)).unwrap();
    let mut screen = Terminal::new(110, 32);
    let start = Instant::now();
    loop {
        for bytes in session.output() {
            let reply = screen.feed(&bytes);
            if !reply.is_empty() {
                let _ = session
                    .input()
                    .send(sentinel_ssh::windows::crypto::Secret(reply));
            }
        }
        if let Some(code) = session.try_wait().unwrap() {
            assert_ne!(code, 0);
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(20));
        std::thread::sleep(Duration::from_millis(10));
    }
    for bytes in session.finish_output() {
        screen.feed(&bytes);
    }
    let text = screen.selection((0, 0), (31, 109), 0).to_lowercase();
    assert!(
        text.contains("connection refused"),
        "Missing OpenSSH terminal output: {text:?}"
    );
    assert!(
        !paths.known_hosts.exists(),
        "Failed pre-handshake connections must not establish trust."
    );
}
