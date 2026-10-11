# SentinelSSH

A Windows-native SSH manager written in Rust. This is an internal preview of the first development slice in [the project plan](secure_ssh_server_manager_project_plan.md).

## Current features

- Resizable dark Win32 workspace with a server sidebar, server-details view, and built-in terminal. No webview or UI framework.
- Master-passphrase setup and unlock, a ten-minute application idle lock, and workstation-lock/suspend handling.
- Add, edit, and delete saved servers: display name, hostname/IP, SSH port, Linux username, and optional identity-file path.
- Choose key/agent authentication or a saved server password encrypted with the master vault's data key.
- CNG AES-256-GCM encryption before ESE storage, with a password-wrapped data key and current-user DPAPI binding.
- System OpenSSH connections inside the app through Windows ConPTY, with an application-specific `known_hosts` file and host-key verification.
- Interactive terminal input, ANSI colours, Unicode text, alternate-screen mode, resizing, bounded scrollback, selection, and copy/paste.
- Confirmed read-only checks: system info, uptime, disk usage, and memory. Output and exit codes remain in the terminal after the command finishes.

The encrypted vault currently holds **host inventory, identity-file references, and saved server passwords**. Saved passwords remain separately encrypted while the inventory is unlocked and are decrypted only for a connection. It does not import or generate private keys. Existing key files and Windows SSH-agent identities remain independent of the vault. Encrypted portable backup, SFTP editing, tags/search, action history, and privileged actions are still planned.

## Run this checkout

The project-local toolchain prepared during development is in the ignored `.tools` directory. This machine has an incomplete MSVC/Windows SDK installation, so use the portable GNU/LLVM build:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\dev.ps1 -Action run -Release -Portable -Offline
```

The updated executable in this checkout is `target\embedded-terminal\release\sentinel-ssh.exe`. A normal build writes `target\release\sentinel-ssh.exe`. `ExecutionPolicy Bypass` applies to this PowerShell process only. The script restores the process environment when it exits and does not change your system PATH.

For a fresh developer machine, install [Rust](https://rust-lang.org/install.html) with the MSVC toolchain and the [MSVC build tools and Windows SDK](https://rust-lang.github.io/rustup/installation/windows-msvc.html). The repository pins Rust 1.90.0 and Microsoft's `windows-sys` 0.61.2 API bindings. Then:

```powershell
cargo run --release --locked
cargo test --locked -- --test-threads=1
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all -- --check
```

The recommended release target is `x86_64-pc-windows-msvc`. The GNU/LLVM build is a development fallback and was checked for imports of Windows system DLLs only; MSVC linking still needs validation on a machine with the complete SDK.

The portable script needs a project-local `1.90.0-x86_64-pc-windows-gnu` toolchain with its `llvm-tools` component, plus the MSVC toolchain's `rustfmt` and `clippy` components. Both toolchains are present in this checkout's `.tools`. A clean clone does not include that directory. The [Rust architecture decision](docs/ADR-001-rust-native-windows.md) explains the dependency policy.

## First connection

1. Enable **OpenSSH Client** in Windows Settings → Optional features if the app reports it missing.
2. Create a long master passphrase and confirm it. There is no password-reset or portable recovery workflow in this preview.
3. Choose **+ New server**, then add a Linux server. Choose **SSH key / agent** and an existing passphrase-protected identity file (blank uses your Windows SSH agent), or **Saved password** and enter the server password. Choose **Save server**.
4. Select the saved server and choose **Connect**. The terminal opens inside the app. Confirm the server's fingerprint against a trusted source before accepting a new host key. Key login prompts in the terminal; saved-password login shows a native fingerprint confirmation dialog.
5. Choose **Server details** to edit a server, or a quick check to preview the target and command before running it in the terminal.

This preview has one active session. Connecting to another server or running a check asks before disconnecting an active session. **Disconnect** ends OpenSSH locally; closing the app also ends its session after confirmation. Remote jobs may respond to SSH disconnection according to their own shell/job settings. Completed output stays visible until the next connection.

Drag to select text; **Ctrl+Shift+C** copies it, and **Ctrl+Shift+V** (or Ctrl+V) pastes up to 32 KiB of UTF-8 text. Ctrl+C without a selection goes to the remote session. Mouse wheel or Shift+PageUp/PageDown browses up to 1,000 lines of history. Arrow, navigation, and function keys go to the session.

The renderer supports common VT cursor/erase/scroll/colour operations and basic wide/combining characters, with a maximum grid of 240 by 120. Advanced mouse reporting, graphics protocols, complete Unicode shaping, and scrollback reflow are not implemented. Compatibility with full-screen Linux programs still requires live-server testing.

To edit a saved password, enter a replacement and save. Leaving the masked field blank keeps the encrypted password; selecting a server never fills or reveals it. Saving key/agent login removes that server's saved password. Passwords may contain spaces and Unicode, with a limit of 1–1022 UTF-8 bytes and no nulls or line breaks. Saved login supports SSH password authentication; keyboard-interactive/MFA and password-expiry challenges remain unsupported. A rejected password gets one attempt; update it and reconnect.

Agent forwarding is disabled. Personal SSH config is bypassed, so jump hosts, custom `ProxyCommand`, and user-config aliases are not supported yet. A changed known host key blocks the connection; this preview does not include a host-key replacement UI. Verify changes independently before maintaining the application trust file manually.

## Data and locking

Data lives under `%LOCALAPPDATA%\SentinelSSH`. The `database` subdirectory contains `vault.edb`, ESE logs, and recovery/checkpoint files. Its ACL grants the current Windows account full access and disables inherited permissions. The database receives only encrypted inventory envelopes.

OpenSSH's `known_hosts` file contains plaintext host identifiers and public host keys inside that protected directory. Selected identity paths are encrypted in the inventory, but existing private-key files are protected according to their own OpenSSH passphrases and filesystem permissions.

Each server password uses AES-256-GCM with a fresh nonce and authenticated credential identifier under the vault's data key. Your master passphrase wraps that key; current-user DPAPI adds Windows-account protection. Decrypted credentials pass through a private, single-use local named pipe to this executable's OpenSSH askpass mode. Neither arguments nor environment variables contain the password, and no plaintext credential file is created. The handoff checks the helper executable, its SSH parent PID, and the pipe owner; pending credentials expire after two minutes.

Locking clears the app's data key, unsaved password field, saved-host view, and pending credential handoffs. **An authenticated connection stays running, but its terminal is hidden and user input is detached until unlock.** Terminal display/history remain in process memory and may receive output while locked; they are not written to disk. Closing or disconnecting ends the connection. Windows SSH-agent identities remain independent. DPAPI binds the vault to the Windows account/device context; copying `vault.edb` alone is not a portable backup. Keep the entire database directory and its logs together when troubleshooting. This preview has no supported restore/migration or master-passphrase-change workflow.

If unlock fails, use **Show master passphrase** to check the input locally, including keyboard layout and leading/trailing spaces. The app restores masking and clears the field after an unlock attempt. `[VAULT_KEY_AUTH]` means the passphrase could not authenticate the wrapped vault key; an incorrect passphrase and a modified encrypted key/header are indistinguishable at this stage. `[VAULT_DATA_AUTH]` means the passphrase verified the key but the encrypted inventory did not authenticate. Other Windows decryption failures retain their status code. Keep the database and logs for investigation and share only the displayed error, never the passphrase. First-run setup now reads back and unlocks the saved record before reporting success.

For developer diagnostics, `examples/vault_inspect.rs` inspects a clean-shutdown **copy** of `vault.edb` in an isolated directory under `.scratch`. It verifies bounded header structure and DPAPI protection without attempting a passphrase, and does not authenticate the encrypted key or inventory. It refuses paths outside the scratch directory; retain the original database/log directory intact.

## Validation

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\dev.ps1 -Action test -Portable -Offline
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\dev.ps1 -Action clippy -Offline
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\dev.ps1 -Action fmt
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\dev.ps1 -Action build -Release -Portable -Offline
```

Tests cover bounded record decoding and legacy key-inventory migration, target/argument injection, Windows quoting, AES-GCM tampering, wrong-password rejection, encrypted-password replacement/preservation, native-control save/lock/reopen behavior, idle/lock/suspend messages, plaintext absence in ESE artifacts, and recovery after forced process termination. Executable-helper tests cover Unicode/space preservation, the maximum password length, single-use delivery, cancellation, wrong parent/owner rejection, and unsupported prompts. ConPTY subprocess tests verify a real console attachment, input, resize, final output, failed-launch cleanup, and shutdown under heavy output. Renderer tests cover fragmented UTF-8/VT, alternate screens, colours, cursor movement, bounded history, and hostile control strings. Tests create isolated temporary directories with disposable fixture data. Native/ESE tests run serially.

The local Windows OpenSSH 9.5p2 configuration was checked with `ssh -G`, including the managed trust path with spaces and both authentication modes. A loopback connection-failure test also verifies the actual system OpenSSH output reaches the embedded terminal. A live Linux password/key login, key-passphrase prompt, host-key mismatch, and remote command execution still need integration testing with disposable Linux hosts. See [the threat model and remaining release gates](docs/THREAT_MODEL.md).

## Source layout

```text
src/core.rs            portable host model, validators, command catalog, record codec
src/windows/ui.rs      native controls and vault/session workflow
src/windows/vault.rs   vault envelope and master-key lifecycle
src/windows/crypto.rs  Windows CNG and DPAPI wrappers
src/windows/storage.rs encrypted-record ESE transactions and recovery
src/windows/paths.rs   per-user paths and Windows ACLs
src/windows/ssh.rs     strict OpenSSH options and fixed remote commands
src/windows/process.rs child process ownership and Windows argument quoting
src/windows/pty.rs     ConPTY hosting, resize, bounded I/O workers and teardown
src/terminal.rs        portable bounded VT display model
src/windows/terminal_view.rs native terminal rendering, keyboard and clipboard
src/windows/theme.rs   dark workspace colours and DPI-scaled fonts
src/windows/askpass.rs  single-use private credential pipe and OpenSSH helper mode
```

License: MIT.
