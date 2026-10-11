# ADR 001: Rust with native Windows services

Status: accepted by the project owner. Updated: 10 October 2026.

## Decision

Implement the Windows-first desktop app in Rust, with Microsoft-maintained Windows API bindings and OS-provided services. Keep application models and command policy independent of the Windows UI. Rust ownership reduces memory-management mistakes in ordinary application code; Windows FFI still requires reviewed `unsafe` boundaries.

| Layer | Selection |
|---|---|
| Application | Rust 2024 edition, pinned Rust 1.90.0 |
| API bindings | `windows-sys` 0.61.2 and its `windows-link` dependency, pinned in `Cargo.lock` |
| UI | Dark, resizable native Win32 controls and GDI terminal view; RichEdit later |
| SSH | System OpenSSH from the Windows system directory |
| Terminal | Windows ConPTY with an application-owned bounded VT renderer |
| Storage | Windows ESENT/ESE, with encryption before record insertion |
| Cryptography | Windows CNG RNG, AES-256-GCM, and PBKDF2-HMAC-SHA-256 |
| Windows binding | Current-user DPAPI around the password-encrypted data key |
| Filesystem | Protected current-user ACLs on the data directories |

Microsoft publishes the [Windows Rust bindings](https://github.com/microsoft/windows-rs); `windows-sys` exposes raw API declarations and ABI types. We build the binding glue into the executable. These crates are dependencies, and Rust's standard library is also used. We therefore describe the policy as **no bundled third-party application frameworks or separately installed app-specific runtime libraries**, with the explicit Microsoft binding exception. We do not claim zero externally authored code.

The application does not bundle or silently install OpenSSH, SQLite, Tauri, Electron, Qt, an SSH library, or a cryptography library. OpenSSH Client is an OS prerequisite. Compiler/linker/SDK tools are development dependencies, outside this runtime policy. Inspect release DLL imports to ensure the selected build does not add an unintended runtime prerequisite.

## Implementation boundary

`src/core.rs` contains portable validation, serialization, and a fixed read-only catalog. Windows-specific modules contain handles, raw pointers, security descriptors, crypto providers, ESE sessions, and GUI controls. Unsafe operations require safety comments and `unsafe_op_in_unsafe_fn` is denied. ESE sessions are explicitly bound to their owning thread.

The first storage schema has one encrypted inventory envelope, replaced in a durable transaction. It supports up to 1,000 hosts with bounded record sizes. Separating identities, trust decisions, and execution history into versioned records belongs to later phases.

The current KDF uses 600,000 PBKDF2-HMAC-SHA-256 iterations and a random 32-byte salt, recorded in the vault header. The data key is generated independently, wrapped by AES-GCM with authenticated header metadata, then protected by current-user DPAPI. Every inventory save uses a fresh random 96-bit GCM nonce. Hardware calibration, format migration, portable export, and independent review remain required before a production release.

OpenSSH runs via `CreateProcessW` with an absolute system executable path, no shell, no inherited handles, and an extended startup attribute attaching it to a ConPTY session. Explicit invalid startup stdio handles prevent parent redirection from overriding the pseudoconsole. Input and output pipes have separate workers; output stays drained during pseudoconsole shutdown. Windows quoting is tested using the system argument parser. `StrictHostKeyChecking=ask` uses a dedicated trust file, personal SSH config is bypassed, and agent forwarding is disabled. Remote checks come only from the compiled command catalog.

The owner added saved-password login to the initial preview. The inventory codec now writes version 2 while reading existing version-1 key records. Each saved password has its own AES-GCM envelope under the vault data key, with a fresh nonce and an authenticated random credential identifier. Unlocking the inventory does not decrypt server passwords. Only launching a saved-password connection decrypts one into a short-lived clearing buffer.

Saved-password connections select password authentication, disable public-key and keyboard-interactive authentication, and permit one password attempt. A per-child environment sets `SSH_ASKPASS` to this executable and `SSH_ASKPASS_REQUIRE=force`; the [Windows OpenSSH prompt implementation](https://github.com/PowerShell/openssh-portable/blob/latestw_all/readpass.c) launches that helper with redirected stdout. The password travels over a single-instance local named pipe with current-user ACLs, a random name, remote-client rejection, executable/parent-PID checks, and owner-PID verification. Only nonsecret handoff context is passed through the environment. Cancellation, vault lock, process exit, or a two-minute deadline clears pending credentials. Host-key prompts show an explicit native confirmation with refusal as the default; unsupported prompts fail closed.

The [ConPTY lifecycle](https://learn.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session) provides process hosting, while `src/terminal.rs` interprets bounded common VT sequences and `terminal_view.rs` draws the cells with GDI. Grid, history, control-string parsing, clipboard paste, and worker queues have explicit limits. Remote OSC/DCS strings cannot write files, alter the clipboard, change the window title, or launch processes. Only an explicit local copy/paste gesture accesses the clipboard. The renderer does not implement full xterm semantics, advanced mouse/graphics protocols, complete Unicode shaping, or scrollback reflow.

One session is active at a time; replacement requires confirmation. Disconnect and app closure tear down OpenSSH and the pseudoconsole while preserving bounded final output for display. Vault locking cancels pending credentials and hides/detaches user input from the terminal; an already authenticated session keeps running and its terminal/history remain in memory. Unlock reattaches user input. External key/agent lifetimes remain separate.

## Consequences

We keep the selected Windows-native runtime model while moving application logic to Rust. Native GUI work, terminal rendering, SSH identity bridging, and portability still require substantial engineering. Rust does not replace the SSH protocol implementation, crypto review, or host-key verification.

The first preview uses existing identity files, the Windows SSH agent, or encrypted saved server passwords. It does not claim that private keys reside exclusively in the encrypted database, or that vault locking revokes an external agent's signing capability or an authenticated SSH session. Portable backup must use a separately designed format rather than copying the DPAPI-bound database.

The recommended build uses MSVC and the Windows SDK, as described in the [Rust Windows tooling guide](https://rust-lang.github.io/rustup/installation/windows-msvc.html). Development here uses the official GNU toolchain and LLVM tools in the ignored `.tools` directory because the installed MSVC setup lacks libraries. That fallback compiled and ran the Windows tests; a full MSVC release build is still a validation gate.

## Next implementation gates

1. Test actual SSH authentication, embedded-terminal interaction, and changed-host-key rejection against disposable Ubuntu/Debian hosts.
2. Prove and document the encrypted-private-key/agent bridge before implementing key management.
3. Implement portable encrypted backup, restore, passphrase changes, and schema migration before storing important production inventory.
4. Complete host organization and action audit, then add SFTP editing and controlled administrative actions.
5. Review the terminal parser/FFI boundaries independently and test full-screen applications, keyboard, Unicode, and resizing against live Linux hosts.
