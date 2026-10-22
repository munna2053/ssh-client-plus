# SentinelSSH

A Windows-native SSH manager written in Rust. This is an internal preview of the first development slice in [the project plan](secure_ssh_server_manager_project_plan.md).

[Download Windows releases](https://github.com/munna2053/ssh-client-plus/releases) · [Release workflow](https://github.com/munna2053/ssh-client-plus/actions/workflows/release.yml)

Published releases include a portable Windows x64 ZIP and SHA-256 checksum. Extract the ZIP and run `sentinel-ssh.exe`; Rust and build tools are not needed. For publishing instructions, see [the release guide](docs/RELEASING.md). Pushing a version tag such as `v0.1.0` builds, checks, packages, and publishes that version on GitHub.

## Current features

- Compact Slint workspace with session tabs, an animated server drawer, a Notepad-style application menu, animated buttons, and keyboard-focus feedback.
- Master-passphrase setup and unlock, a ten-minute application idle lock, and workstation-lock/suspend handling.
- Add, edit, and delete saved servers: display name, hostname/IP, SSH port, Linux username, and optional identity-file path.
- Servers ordered by their most recent connection, saved across restarts, with vertical scrolling when the drawer overflows.
- Choose key/agent authentication or a saved server password encrypted with the master vault's data key.
- CNG AES-256-GCM encryption before ESE storage, with a password-wrapped data key and current-user DPAPI binding.
- System OpenSSH connections inside the app through Windows ConPTY, with an application-specific `known_hosts` file and host-key verification.
- Interactive terminal input, ANSI colours, Unicode text, alternate-screen mode, resizing, bounded scrollback, selection, and copy/paste.
- 28 built-in command shortcuts for Linux diagnostics, processes, networking, services/logs, Docker/Compose, and Kubernetes, plus up to 100 custom shortcuts saved in the encrypted vault. Choosing a shortcut inserts its command into the active terminal; press Enter to run it.
- Settings view with a selectable database path, copy-location button, master-passphrase change, custom-shortcut management, and confirmed removal of all saved servers and passwords.

The encrypted vault currently holds **host inventory, identity-file references, saved server passwords, and custom command shortcuts**. Saved passwords remain separately encrypted while the inventory is unlocked and are decrypted only for a connection. The server editor can generate Ed25519 key pairs as local OpenSSH files with an optional key passphrase. Key files and Windows SSH-agent identities remain independent of the vault. Encrypted portable backup, SFTP editing, tags/search, action history, and privileged actions are still planned.

## Run this checkout

The project-local toolchain prepared during development is in the ignored `.tools` directory. This machine has an incomplete MSVC/Windows SDK installation, so use the portable GNU/LLVM build:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\dev.ps1 -Action run -Release -Portable -Offline
```

The updated executable built by the script is `target\slint\release\sentinel-ssh.exe`. A direct Cargo build writes `target\release\sentinel-ssh.exe`. `ExecutionPolicy Bypass` applies to this PowerShell process only. The script restores the process environment when it exits and does not change your system PATH.

To review the UI with disposable sample servers and terminal output:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\dev.ps1 -Action run -Portable -Offline -Preview
```

Preview mode uses a temporary workspace in `.scratch` and does not load your real vault or connect to the sample hosts. The frontend uses Slint 1.13.1, pinned for compatibility with the Rust toolchain. Its About screen includes Slint's attribution widget. See [the Slint frontend decision](docs/ADR-002-slint-windows-frontend.md).

For a fresh developer machine, install [Rust](https://rust-lang.org/install.html) with the MSVC toolchain and the [MSVC build tools and Windows SDK](https://rust-lang.github.io/rustup/installation/windows-msvc.html). The repository pins Rust 1.90.0 and Microsoft's `windows-sys` 0.61.2 API bindings. Then:

```powershell
cargo run --release --locked
cargo test --locked -- --test-threads=1
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all -- --check
```

The recommended release target is `x86_64-pc-windows-msvc`. The GNU/LLVM build is a development fallback and was checked for imports of Windows system DLLs only; MSVC linking still needs validation on a machine with the complete SDK.

The portable script needs a project-local `1.90.0-x86_64-pc-windows-gnu` toolchain with `llvm-tools` and `clippy`, plus the MSVC toolchain's `rustfmt`. Both toolchains are present in this checkout's `.tools`. A clean clone does not include that directory. The [Slint frontend decision](docs/ADR-002-slint-windows-frontend.md) documents the current UI dependencies and linker tooling.

## First connection

1. Enable **OpenSSH Client** in Windows Settings → Optional features if the app reports it missing.
2. Create a long master passphrase and confirm it. There is no password-reset or portable recovery workflow in this preview.
3. Open **Servers → New server**, or choose **⋯ → New server**, then add a Linux server. Choose **SSH key / agent** and an existing passphrase-protected identity file (blank uses your Windows SSH agent), or **Saved password** and enter the server password. Choose **Save server**.
4. Choose **Connect** on a server card to open a new session tab. Confirm the server's fingerprint against a trusted source before accepting a new host key. Key login prompts in the terminal; saved-password login shows a native fingerprint confirmation dialog.
5. Choose **Edit** on a server card to edit or delete that server; **Done** returns to the sessions. With a session active, use **Shortcuts** beside the session tabs to insert a command. Edit it as needed, then press Enter in the terminal to run it.

Up to 16 session tabs can stay open, each with its own terminal and bounded history. Connecting opens a new tab and keeps existing sessions running. Switch tabs to select the terminal; arrows reveal tabs when the row fills. Command shortcuts insert text into the selected session, including when a different saved server is selected for editing. The **×** button closes that tab and asks before disconnecting a running session; closing the app asks before ending all running sessions. Remote jobs may respond to SSH disconnection according to their own shell/job settings. Completed output stays in its tab until you close it.

The terminal uses nearly the full window below a single compact row of tabs. **Servers** opens or closes the left drawer with server-card **Connect** and **Edit** buttons and **+ New server**. The drawer starts closed and closes when you open a session or server editor. The **⋯** menu contains the app logo, vault status, **New server**, server-drawer controls, **Settings**, **Lock vault**, **About**, and keyboard help. Escape or a click outside dismisses the menu and restores the terminal. **Shortcuts** and **Settings** stay beside the session tabs.

Opening an SSH connection moves that server to the top of the drawer. The order is stored in the encrypted inventory and survives locking and restarting. Editing a server keeps its position; newly saved servers appear below existing entries until connected. An SSH launch that fails before opening a session leaves the order unchanged. Existing saved servers keep their current order until you connect with this version. Overflowing server lists support the mouse wheel and a vertical scrollbar; **+ New server** stays below the scrolling cards.

Open **Settings** after unlocking to view or copy the `vault.edb` location. **Change vault key** requires the current master passphrase and a matching new passphrase of at least 12 characters. The change preserves saved servers, encrypted server passwords, and custom shortcuts. It takes effect for future unlocks after the database transaction succeeds; existing database copies still require their original passphrase.

Choose **Shortcuts → + New shortcut** or **Settings → + New shortcut** to save a name and a single-line command. Shortcut management is available before connecting; inserting a command requires a running session. Commands are encrypted with the inventory and are never executed automatically. Custom shortcuts can be removed in Settings; built-in shortcuts are retained.

The built-in catalog includes CPU/block-device details, directory sizes, top CPU/memory processes, users/logins, IP addresses/routes, listening ports/connections, failed/running services, recent logs/errors, Docker containers/disk usage/resource usage, Compose services, and Kubernetes pods/nodes/deployments/events. The Shortcuts menu scrolls when its contents overflow. Commands run on the selected server and require the relevant tools and permissions there. Docker and Kubernetes syntax follows the [Docker CLI reference](https://docs.docker.com/reference/cli/docker/) and [kubectl quick reference](https://kubernetes.io/docs/reference/kubectl/quick-reference/).

**Settings → Delete all server data...** requires typing `DELETE` and pressing the final delete button. It removes every saved server and password and closes all session tabs, including their terminal history. The vault passphrase, custom shortcuts, local SSH key files, and OpenSSH host trust entries are retained. This removes the current inventory; it does not securely erase previous ciphertext in ESE logs or existing database copies.

The session-close confirmation includes an initially unchecked **Do not show this again** option. Check it and choose **Yes** to skip future tab-close prompts, including after restarting the app. Choosing **No** keeps the tab open and does not save the checkbox. To restore tab-close prompts, close the app and remove `%LOCALAPPDATA%\SentinelSSH\skip-session-close-confirmation`.

To create a key for a new server, choose **SSH key / agent → Create SSH key pair**. Enter and confirm an optional key passphrase, then choose **Generate key pair**. The app fills in the saved private-key path and shows the public key with a **Copy public key** button. Add that public key to the server account's `~/.ssh/authorized_keys`, then save the server. The public-key display is available again when you edit the saved server. Generation runs in the background and is cancelled if you close the editor or lock the vault.

Generated pairs live in `%LOCALAPPDATA%\SentinelSSH\keys\<unique-id>\id_ed25519` and `id_ed25519.pub`, restricted to your Windows account. Each generation uses a new directory and preserves existing keys. The optional key passphrase encrypts the private key in OpenSSH format; it is separate from the vault master passphrase and is never saved by the app. OpenSSH prompts for it in the terminal when connecting unless the key is already in your SSH agent. With a blank passphrase, file permissions protect the unencrypted private key. Vault locking does not encrypt or remove completed key files. Completed pairs remain on disk even if you discard or delete their server entry; unfinished, unpublished pairs are cleaned up on cancellation.

Drag to select text; **Ctrl+Shift+C** copies it, and **Ctrl+Shift+V** (or Ctrl+V) pastes up to 32 KiB of UTF-8 text. Ctrl+C without a selection goes to the remote session. Mouse wheel or Shift+PageUp/PageDown browses up to 1,000 lines of history. Arrow, navigation, and function keys go to the session.

The renderer supports common VT cursor/erase/scroll/colour operations and basic wide/combining characters, with a maximum grid of 240 by 120. Advanced mouse reporting, graphics protocols, complete Unicode shaping, and scrollback reflow are not implemented. Compatibility with full-screen Linux programs still requires live-server testing.

To edit a saved password, enter a replacement and save. Leaving the masked field blank keeps the encrypted password; selecting a server never fills or reveals it. Saving key/agent login removes that server's saved password. Passwords may contain spaces and Unicode, with a limit of 1–1022 UTF-8 bytes and no nulls or line breaks. Saved login supports SSH password authentication; keyboard-interactive/MFA and password-expiry challenges remain unsupported. A rejected password gets one attempt; update it and reconnect.

Agent forwarding is disabled. Personal SSH config is bypassed, so jump hosts, custom `ProxyCommand`, and user-config aliases are not supported yet. A changed known host key blocks the connection; this preview does not include a host-key replacement UI. Verify changes independently before maintaining the application trust file manually.

## Data and locking

Data lives under `%LOCALAPPDATA%\SentinelSSH`. The `database` subdirectory contains `vault.edb`, ESE logs, and recovery/checkpoint files. Its ACL grants the current Windows account full access and disables inherited permissions. The database receives only encrypted inventory envelopes.

OpenSSH's `known_hosts` file contains plaintext host identifiers and public host keys inside that protected directory. Selected identity paths are encrypted in the inventory, but existing private-key files are protected according to their own OpenSSH passphrases and filesystem permissions.

Each server password uses AES-256-GCM with a fresh nonce and authenticated credential identifier under the vault's data key. Your master passphrase wraps that key; current-user DPAPI adds Windows-account protection. Decrypted credentials pass through a private, single-use local named pipe to this executable's OpenSSH askpass mode. Neither arguments nor environment variables contain the password, and no plaintext credential file is created. The handoff checks the helper executable, its SSH parent PID, and the pipe owner; pending credentials expire after two minutes.

Locking clears the app's data key, unsaved password field, saved-host and shortcut views, settings inputs, and pending credential handoffs. **Authenticated connections stay running, but all terminals and session tabs are hidden and user input is detached until unlock.** Terminal display/history remain in process memory and may receive output while locked; they are not written to disk. Closing a tab ends its connection; closing the app ends all connections. Windows SSH-agent identities remain independent. DPAPI binds the vault to the Windows account/device context; copying `vault.edb` alone is not a portable backup. Keep the entire database directory and its logs together when troubleshooting. Settings supports master-passphrase changes; portable restore and moving the database are not supported yet.

If unlock fails, use **Show master passphrase** to check the input locally, including keyboard layout and leading/trailing spaces. The app restores masking and clears the field after an unlock attempt. `[VAULT_KEY_AUTH]` means the passphrase could not authenticate the wrapped vault key; an incorrect passphrase and a modified encrypted key/header are indistinguishable at this stage. `[VAULT_DATA_AUTH]` means the passphrase verified the key but the encrypted inventory did not authenticate. Other Windows decryption failures retain their status code. Keep the database and logs for investigation and share only the displayed error, never the passphrase. First-run setup now reads back and unlocks the saved record before reporting success.

For developer diagnostics, `examples/vault_inspect.rs` inspects a clean-shutdown **copy** of `vault.edb` in an isolated directory under `.scratch`. It verifies bounded header structure and DPAPI protection without attempting a passphrase, and does not authenticate the encrypted key or inventory. It refuses paths outside the scratch directory; retain the original database/log directory intact.

## Validation

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\dev.ps1 -Action test -Portable -Offline
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\dev.ps1 -Action clippy -Portable -Offline
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\dev.ps1 -Action fmt
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\dev.ps1 -Action build -Release -Portable -Offline
```

Tests cover bounded record decoding and legacy key-inventory migration, target/argument injection, Windows quoting, AES-GCM tampering, wrong-password rejection, encrypted-password replacement/preservation, native-control save/lock/reopen behavior, idle/lock/suspend messages, plaintext absence in ESE artifacts, and recovery after forced process termination. Settings smoke tests verify master-passphrase changes preserve passwords, invalid inputs leave the vault unchanged, custom shortcuts persist, locking clears settings inputs, and bulk server deletion requires confirmation and closes tabs. Executable-helper tests cover Unicode/space preservation, the maximum password length, single-use delivery, cancellation, wrong parent/owner rejection, and unsupported prompts. ConPTY subprocess tests verify a real console attachment, input, resize, final output, failed-launch cleanup, and shutdown under heavy output. Renderer tests cover fragmented UTF-8/VT, alternate screens, colours, cursor movement, bounded history, and hostile control strings. Tests create isolated temporary directories with disposable fixture data. Native/ESE tests run serially.

On a Windows desktop, run `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\check-window-restore.ps1` after the release build to check the presented compact row and terminal across six minimize/restore cycles, including maximized windows. This uses disposable preview data and never opens the real vault or SSH connections. Pass `-Executable <path>` to check a different build.

The local Windows OpenSSH 9.5p2 configuration was checked with `ssh -G`, including the managed trust path with spaces and both authentication modes. A loopback connection-failure test also verifies the actual system OpenSSH output reaches the embedded terminal. A live Linux password/key login, key-passphrase prompt, host-key mismatch, and remote command execution still need integration testing with disposable Linux hosts. See [the threat model and remaining release gates](docs/THREAT_MODEL.md).

## Source layout

```text
src/core.rs            portable host model, validators, command catalog, record codec
ui/                    Slint workspace and animated controls
src/windows/slint_frontend.rs  Slint callbacks and native terminal hosting
src/windows/ui.rs      legacy native workspace retained for regression tests
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
src/windows/keygen.rs   background OpenSSH key generation and public-key loading
```

License: MIT.
