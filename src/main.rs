#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    #[cfg(windows)]
    if sentinel_ssh::windows::askpass::is_helper() {
        let result = sentinel_ssh::windows::askpass::run_helper();
        std::process::exit(if result.is_ok() { 0 } else { 1 });
    }

    #[cfg(windows)]
    if let Err(error) = sentinel_ssh::windows::slint_frontend::run() {
        if std::env::args().any(|argument| argument == "--ui-smoke-test") {
            eprintln!("Slint UI smoke test failed: {error}");
            std::process::exit(1);
        }
        sentinel_ssh::windows::ui::show_error(&error);
    }

    #[cfg(not(windows))]
    eprintln!("SentinelSSH currently supports Windows 11 only.");
}
