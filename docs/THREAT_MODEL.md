# SentinelSSH preview threat model

Updated: 10 October 2026. Scope: the Rust Windows-native inventory/SSH preview.

## Assets and boundaries

The application protects stored host inventory, identity-file references, and its data-encryption key. It delegates SSH protocol security and key authentication to the Windows OpenSSH Client. Existing identity files, Windows SSH-agent identities, remote hosts, and separate console sessions have independent lifecycles.

| Scenario | Current control | Limit |
|---|---|---|
| Copied database/log files | Encrypt inventory before ESE insertion; password-wrapped data key plus current-user DPAPI | Account/device recovery and portable restore are not implemented |
| Modified ciphertext/header | AES-GCM authentication and bounded, versioned decoding | Does not detect rollback of an entire previously valid vault |
| Password guessing in the UI | Master-passphrase requirement, PBKDF2 cost, bounded retry delays | Same-user malware can bypass UI controls; offline attacks still require threat review |
| Another ordinary Windows user | Protected current-user directory ACLs; reject app-directory reparse points | Administrators can take ownership; ancestor/path races need further review |
| Unknown/changed SSH host | Dedicated OpenSSH trust file; explicit first-use fingerprint prompt; changed-key rejection | The user must verify first-use keys through a trusted source; live mismatch tests remain |
| Malicious target/arguments | Host/user validation, fixed commands, native process launch and tested quoting | The remote host controls output; embedded rendering is not implemented |
| Workstation lock/suspend or app inactivity | WTS/power messages, ten-minute app idle timer, data-key clearing | External SSH sessions and agent identities remain usable |
| Abrupt process exit during save | Durable ESE transaction; tests force process termination after commit and during an uncommitted update | Backup/restore and broader corruption/recovery testing remain |

## Cryptographic design

Use only Windows CNG and DPAPI for cryptographic operations. The current vault header records a format marker/version, PBKDF2 iteration count, random salt, and DPAPI-protected encrypted data key. AES-256-GCM authenticates the wrapped key against version/KDF/salt metadata. A separate authenticated envelope contains the inventory. Passwords are not stored or sent on process command lines.

Secret buffers owned by the application are cleared with volatile writes before release, and CNG handles are destroyed through ownership wrappers. This is best-effort clearing: copies in Windows edit controls, the allocator, paging, system dumps, and third-party processes cannot be guaranteed erased. No claim is made against malware running as the unlocked user, an administrator, or a compromised remote host.

The application-specific `known_hosts` file is plaintext and contains public host keys and host identifiers. It is protected by the data-directory ACL. Existing SSH identity files are never imported into the vault in this slice; use passphrase-protected files or an independently managed agent. The app does not inspect or enforce the encryption of an external identity file.

## Release gates still open

- Independent review of crypto wrappers, key lifecycle, file permissions, FFI ownership, and serialized formats.
- Real Linux-host tests: first-use fingerprint verification, changed-key hard failure, passphrase prompts, agent interoperability, disconnection, and read-only output/exit codes.
- Supported portable backup/restore, passphrase change, KDF calibration, and version migration.
- Verified private-key import/generation/agent bridge, including lock-time signing revocation policy.
- Complete MSVC/Windows SDK build and Windows version/architecture test matrix.
- Malicious terminal output, broader ESE corruption/recovery, and local filesystem race testing.
- Installer, signing, update policy, and production diagnostics that avoid secrets.

Do not treat the current preview as completion of the full private-key-vault or production-release scope in the project plan.
