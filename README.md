# SentinelSSH

A Windows-native SSH manager written in Rust. This is an internal preview of the first development slice in [the project plan](secure_ssh_server_manager_project_plan.md).

## Current features

- Native Win32 desktop controls, without a webview or UI framework.
- Master-passphrase setup and unlock, a ten-minute application idle lock, and workstation-lock/suspend handling.
- Add, edit, and delete saved servers: display name, hostname/IP, SSH port, Linux username, and optional identity-file path.
- CNG AES-256-GCM encryption before ESE storage, with a password-wrapped data key and current-user DPAPI binding.
- System OpenSSH connections in a separate interactive Windows console, with an application-specific `known_hosts` file and host-key verification.
- Confirmed read-only checks: system info, uptime, disk usage, and memory. The console shows the command exit code and waits for Enter.

The encrypted vault currently holds **host inventory and identity-file references**. It does not import or generate private keys. Existing key files and Windows SSH-agent identities remain independent of the vault. Embedded terminals, encrypted portable backup, SFTP editing, tags/search, action history, and privileged actions are still planned.

## Run this checkout

The project-local toolchain prepared during development is in the ignored `.tools` directory. This machine has an incomplete MSVC/Windows SDK installation, so use the portable GNU/LLVM build:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\dev.ps1 -Action run -Release -Portable -Offline
```

Or open the built executable at `target\release\sentinel-ssh.exe`. `ExecutionPolicy Bypass` applies to this PowerShell process only. The script restores the process environment when it exits and does not change your system PATH.

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
3. Add a Linux server and save it. Use an existing passphrase-protected OpenSSH identity file, or leave the path blank to use your Windows SSH agent.
4. Select the saved server and choose **Open SSH terminal**. Confirm the server's fingerprint against a trusted source before accepting a new host key in the console.
5. Choose a read-only check to preview the target and command before launching it.

OpenSSH password login and agent forwarding are disabled. Personal SSH config is bypassed, so jump hosts, custom `ProxyCommand`, and user-config aliases are not supported yet. A changed known host key blocks the connection; this preview does not include a host-key replacement UI. Verify changes independently before maintaining the application trust file manually.

## Data and locking

Data lives under `%LOCALAPPDATA%\SentinelSSH`. The `database` subdirectory contains `vault.edb`, ESE logs, and recovery/checkpoint files. Its ACL grants the current Windows account full access and disables inherited permissions. The database receives only encrypted inventory envelopes.

OpenSSH's `known_hosts` file contains plaintext host identifiers and public host keys inside that protected directory. Selected identity paths are encrypted in the inventory, but existing private-key files are protected according to their own OpenSSH passphrases and filesystem permissions.

Locking clears the app's data key and saved-host view. **Existing SSH consoles and agent identities remain available.** DPAPI binds the vault to the Windows account/device context; copying `vault.edb` alone is not a portable backup. Keep the entire database directory and its logs together when troubleshooting. This preview has no supported restore/migration or password-change workflow.

## Validation

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\dev.ps1 -Action test -Portable -Offline
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\dev.ps1 -Action clippy -Offline
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\dev.ps1 -Action fmt
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\dev.ps1 -Action build -Release -Portable -Offline
```

Tests cover bounded record decoding, target/argument injection, Windows quoting, AES-GCM tampering, wrong-password rejection, native-control save/lock/reopen behavior, idle/lock/suspend messages, plaintext absence in ESE artifacts, and recovery after forced process termination. Tests create isolated temporary directories with disposable fixture data. Native/ESE tests run serially.

The local Windows OpenSSH 9.5p2 configuration was checked with `ssh -G`, including the managed trust path with spaces. A live Linux login, key-passphrase prompt, host-key mismatch, and remote command execution still need integration testing with disposable Linux hosts. See [the threat model and remaining release gates](docs/THREAT_MODEL.md).

## Source layout

```text
src/core.rs            portable host model, validators, command catalog, record codec
src/windows/ui.rs      native controls and vault/session workflow
src/windows/vault.rs   vault envelope and master-key lifecycle
src/windows/crypto.rs  Windows CNG and DPAPI wrappers
src/windows/storage.rs encrypted-record ESE transactions and recovery
src/windows/paths.rs   per-user paths and Windows ACLs
src/windows/ssh.rs     strict OpenSSH options and fixed remote commands
src/windows/process.rs native console launch and Windows argument quoting
```

License: MIT.
