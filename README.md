# SentinelSSH

A Windows-native SSH manager written in Rust. It keeps your servers, saved passwords, and command shortcuts in an encrypted local vault and connects through the Windows OpenSSH Client in built-in terminal tabs.

> **Preview:** SentinelSSH is still in development. See the [threat model](docs/THREAT_MODEL.md) for its security limits and the open release gates.

## Download

1. Download `sentinel-ssh-<version>-windows-x64.zip` from [Releases](https://github.com/munna2053/ssh-client-plus/releases).
2. Extract it and run `sentinel-ssh.exe`. Nothing else needs to be installed.

**Requirements:** Windows 11 x64 with the **OpenSSH Client** optional feature (Settings → System → Optional features).

The executable is not code-signed yet, so Windows SmartScreen may warn you the first time you run it. You can check the download against its `.sha256` file:

```powershell
Get-FileHash .\sentinel-ssh-<version>-windows-x64.zip -Algorithm SHA256
```

## Features

- **Encrypted vault:** your servers, saved passwords, and shortcuts are encrypted with AES-256-GCM under your master passphrase and tied to your Windows account through DPAPI.
- **Terminal tabs:** up to 16 SSH sessions, each with colours, Unicode, resizing, selection, copy/paste, and 1,000 lines of scrollback.
- **Authentication:** SSH key or agent, or a saved password that is only decrypted when you connect.
- **SSH key generation:** create Ed25519 key pairs in the app and copy the public key to your server.
- **Host-key checking:** you confirm a new server's fingerprint. A changed host key blocks the connection.
- **Command shortcuts:** 28 built-in Linux, Docker, and Kubernetes commands, plus up to 100 of your own. A shortcut types its command into the terminal; press Enter to run it.
- **Auto-lock:** the vault locks after 10 minutes of inactivity, when you lock Windows, or when the PC sleeps.

## Getting started

1. Run the app and create a long master passphrase. **There is no way to recover a forgotten passphrase.**
2. Choose **Servers → + New server**. Enter the host, port, and username, then pick one:
   - **SSH key / agent:** select an identity file, leave it blank to use your Windows SSH agent, or choose **Create SSH key pair**.
   - **Saved password:** enter the server password.
3. Choose **Save server**, then **Connect** on the server card.
4. Check the fingerprint against a trusted source before accepting a new server.

### Keyboard

| Action | Keys |
|---|---|
| Copy selection | Ctrl+Shift+C |
| Paste (up to 32 KiB) | Ctrl+Shift+V or Ctrl+V |
| Scroll history | Mouse wheel, Shift+PageUp / Shift+PageDown |
| Interrupt the remote command | Ctrl+C (with no selection) |

## Your data

- Everything is stored in `%LOCALAPPDATA%\SentinelSSH`, readable only by your Windows account.
- The vault only opens under your Windows account on this PC. Copying `vault.edb` to another PC does not work as a backup.
- Locking hides your sessions and stops keyboard input to them, but **connections stay open**. Close a tab to disconnect.
- **Settings** lets you change the master passphrase, manage shortcuts, and delete all saved servers.

### Not supported yet

- Your personal SSH config: jump hosts, `ProxyCommand`, and host aliases
- Agent forwarding, MFA or keyboard-interactive logins, and password-expiry prompts
- Replacing a changed host key in the app
- Backup and restore, SFTP, and tags or search

## Build from source

Use the Rust version pinned in `rust-toolchain.toml` (1.90.0).

**With the Visual Studio C++ build tools** (MSVC):

```powershell
cargo run --release --locked
cargo test --locked -- --test-threads=1
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all -- --check
```

**Without Visual Studio** (portable GNU/LLVM build): download `rustup-init.exe` from [rustup.rs](https://rustup.rs), install Rust into the ignored `.tools` folder, then use `scripts\dev.ps1`. This doesn't change your system PATH.

```powershell
$env:RUSTUP_HOME = "$PWD\.tools\rustup"; $env:CARGO_HOME = "$PWD\.tools\cargo"
rustup-init.exe -y --no-modify-path --default-toolchain none
.\.tools\cargo\bin\rustup toolchain install 1.90.0-x86_64-pc-windows-gnu --profile minimal -c clippy -c llvm-tools
.\.tools\cargo\bin\rustup toolchain install 1.90.0-x86_64-pc-windows-msvc --profile minimal -c rustfmt

.\scripts\dev.ps1 -Action run -Release -Portable    # build and run
.\scripts\dev.ps1 -Action test -Portable            # also: clippy, fmt, build
.\scripts\dev.ps1 -Action run -Portable -Preview    # UI preview with sample data
```

Preview mode uses a temporary workspace in `%TEMP%`. It never opens your real vault or connects to the sample servers. If PowerShell blocks the scripts, run them with `powershell -ExecutionPolicy Bypass -File <script> ...`.

## Project layout

```text
src/core.rs                    host model, validation, command catalog, record format
src/terminal.rs                VT terminal model
src/windows/slint_frontend.rs  Slint UI logic and terminal hosting
src/windows/terminal_view.rs   terminal rendering, keyboard, and clipboard
src/windows/vault.rs           vault encryption and master key
src/windows/crypto.rs          Windows CNG and DPAPI wrappers
src/windows/storage.rs         ESE database storage
src/windows/ssh.rs             OpenSSH launch options
src/windows/askpass.rs         one-time password handoff to OpenSSH
src/windows/pty.rs             ConPTY sessions
src/windows/keygen.rs          SSH key generation
ui/                            Slint UI files
assets/icon/                   application icon sources and .ico
build.rs                       embeds the icon in the executable
```

## Documentation

- [Releasing](docs/RELEASING.md): publish a version and update the icon
- [Threat model](docs/THREAT_MODEL.md) and [security assessment](docs/SECURITY_ASSESSMENT.md)
- [Roadmap](docs/ROADMAP.md) and [project plan](secure_ssh_server_manager_project_plan.md)
- Design decisions: [Rust on Windows](docs/ADR-001-rust-native-windows.md), [Slint frontend](docs/ADR-002-slint-windows-frontend.md)

## License

MIT. See [LICENSE](LICENSE).
