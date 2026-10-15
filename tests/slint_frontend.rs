#![cfg(windows)]

#[test]
fn slint_callbacks_save_encrypt_lock_reopen_and_keep_tabs_separate() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_sentinel-ssh"))
        .arg("--ui-smoke-test")
        .output()
        .expect("Start the disposable Slint UI smoke test");
    assert!(
        output.status.success(),
        "Slint smoke test failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
