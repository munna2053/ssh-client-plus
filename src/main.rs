#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    #[cfg(windows)]
    if let Err(error) = sentinel_ssh::windows::ui::run() {
        sentinel_ssh::windows::ui::show_error(&error);
    }

    #[cfg(not(windows))]
    eprintln!("SentinelSSH currently supports Windows 11 only.");
}
