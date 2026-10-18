# SentinelSSH preview threat model

Updated: 17 October 2026. Scope: the Rust Windows-native inventory/SSH preview.

## Assets and boundaries

The application protects stored host inventory, identity-file references, saved server passwords, custom command shortcuts, and its data-encryption key. It delegates SSH protocol security and authentication to the Windows OpenSSH Client. Existing identity files, Windows SSH-agent identities, remote hosts, and authenticated SSH sessions have independent security lifecycles.

| Scenario | Current control | Limit |
|---|---|---|
| Copied database/log files | Encrypt inventory before ESE insertion; password-wrapped data key plus current-user DPAPI | Account/device recovery and portable restore are not implemented |
| Modified ciphertext/header | AES-GCM authentication and bounded, versioned decoding | Does not detect rollback of an entire previously valid vault |
| Password guessing in the UI | Master-passphrase requirement, PBKDF2 cost, bounded retry delays | Same-user malware can bypass UI controls; offline attacks still require threat review |
| Another ordinary Windows user | Protected current-user directory ACLs; reject app-directory reparse points | Administrators can take ownership; ancestor/path races need further review |
| Unknown/changed SSH host | Dedicated OpenSSH trust file; explicit first-use fingerprint prompt; changed-key rejection | The user must verify first-use keys through a trusted source; live mismatch tests remain |
| Malicious target/arguments | Host/user validation, fixed commands, native process launch and tested quoting | The remote host controls rendered text; terminal compatibility and independent parser review remain |
| Malicious terminal output | Bounded VT state/history/queries, no OSC/DCS side effects, bounded worker queues, local gestures required for clipboard | A remote host can display misleading text; shaping/reflow and full xterm compatibility are incomplete |
| Credential theft through launch arguments/files | Passwords remain separately encrypted until launch; private per-user single-use named pipe; helper image/parent and owner-PID checks; no password in argv/environment/temp files | Same-user malware can inspect process memory or interfere; OpenSSH receives plaintext to authenticate |
| Workstation lock/suspend or app inactivity | WTS/power messages, ten-minute app idle timer, data-key clearing | Authenticated SSH continues; display/history stay in memory while hidden and input is detached. Agent identities remain usable independently |
| Abrupt process exit during save | Durable ESE transaction; tests force process termination after commit and during an uncommitted update | Backup/restore and broader corruption/recovery testing remain |

## Cryptographic design

Use only Windows CNG and DPAPI for cryptographic operations. The current vault header records a format marker/version, PBKDF2 iteration count, random salt, and DPAPI-protected encrypted data key. AES-256-GCM authenticates the wrapped key against version/KDF/salt metadata. A separate authenticated envelope contains the inventory. Each saved server password has a separate AES-GCM envelope under the same data key, a fresh 96-bit nonce, and a random credential identifier authenticated as associated data. The master passphrase is never saved. Server passwords are saved only as ciphertext and remain encrypted in the unlocked inventory.

Connection launch decrypts only the selected credential. A clearing buffer passes through a private, remote-rejecting named pipe to the executable's askpass helper. The broker verifies the helper executable and SSH-parent PID; the helper verifies the pipe server's PID. Credentials are not placed in arguments, environment values, or plaintext files. A single delivery, cancellation, window closure, or two-minute timeout clears the broker's buffer. Vault lock cancels all pending brokers; it cannot retract a credential already delivered to OpenSSH. Password mode disables keyboard-interactive and limits prompts to one. Host-key confirmation never requests or receives the server password. Existing host inventory versions 1 and 2 remain readable. New saves use a versioned workspace payload containing host inventory version 2 and bounded custom shortcuts; older application versions cannot read this expanded payload.

Settings changes the master passphrase only after verifying the current passphrase, with the same retry delays as unlock. A fresh salt and wrapping key protect the existing data key, preserving encrypted server passwords. The replacement envelope is verified before a durable ESE transaction replaces the record. Existing database copies retain their original wrapping keys; this does not revoke old copies or rotate the underlying data key. Bulk server deletion requires an explicit typed confirmation, commits an empty host inventory, and closes all sessions. It preserves custom shortcuts, key files, and host trust entries and does not securely erase old ciphertext in ESE logs or backups. Custom commands reject control characters and line breaks and are inserted without Enter; they run only after user input in the terminal.

Secret buffers owned by the application are cleared with volatile writes before release, and CNG handles are destroyed through ownership wrappers. This is best-effort clearing: copies in Windows edit controls, the allocator, paging, system dumps, and third-party processes cannot be guaranteed erased. No claim is made against malware running as the unlocked user, an administrator, or a compromised remote host.

The application-specific `known_hosts` file is plaintext and contains public host keys and host identifiers. It is protected by the data-directory ACL. Existing SSH identity files are never imported into the vault in this slice; use passphrase-protected files or an independently managed agent. The app does not inspect or enforce the encryption of an external identity file.

## Release gates still open

- Independent review of crypto wrappers, key lifecycle, file permissions, FFI ownership, and serialized formats.
- Real Linux-host tests: saved-password/key login, wrong-password rejection, first-use fingerprint verification, changed-key hard failure, passphrase prompts, agent interoperability, disconnection, and read-only output/exit codes.
- Supported portable backup/restore, KDF calibration, and broader version migration.
- Verified private-key import/generation/agent bridge, including lock-time signing revocation policy.
- Complete MSVC/Windows SDK build and Windows version/architecture test matrix.
- Independent hostile-output/parser review and broader terminal fuzzing; ESE corruption/recovery and local filesystem race testing.
- Installer, signing, update policy, and production diagnostics that avoid secrets.

Do not treat the current preview as completion of the full private-key-vault or production-release scope in the project plan.
