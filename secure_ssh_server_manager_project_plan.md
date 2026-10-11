# Secure SSH Server Manager — Product and Engineering Plan

**Document status:** Rust architecture selected; first native preview implemented; full MVP gates remain open<br>
**Prepared:** 8 October 2026  
**Revised:** 10 October 2026<br>
**Target v1 client:** Windows 11 (Windows 10 only after compatibility validation)  
**Target v1 managed hosts:** Linux servers over SSH  
**Later clients:** macOS, then Linux  
**Working product name:** SentinelSSH (placeholder; trademark/domain availability not checked)

---

## 1. Executive decision

Build a **local-first, security-oriented desktop SSH manager** that combines an encrypted private-key vault, Linux host inventory, SSH terminal, safe administrative actions, and remote text editing.

**Feasible?** Yes, with an important qualification: a modern, trustworthy SSH client, terminal emulator, and encrypted database are major projects in their own right. The selected Windows-first design is a native **Rust/Win32** application, allowing Microsoft-maintained Rust API bindings while avoiding bundled third-party application frameworks, using:

- **Windows platform APIs** for UI, cryptography, storage, and process execution.
- **Microsoft-provided OpenSSH Client** (`ssh.exe`, `ssh-keygen.exe`, `sftp.exe`, optionally `ssh-agent.exe`) as an **operating-system component that must be present/enabled**.
- A **Windows-native ESENT/ESE database** storing **application-encrypted records**, not plain SSH keys.
- A separate master-password unlock mechanism (not merely a cosmetic login screen).
- **Microsoft's `windows-sys`/`windows-link` crates**, with pinned versions and reviewed unsafe wrappers around Windows APIs.

This requires **no bundled UI framework or separately installed app-specific runtime library**. Rust's standard library and Microsoft API-binding glue are compiled into the executable; those are explicit permitted dependencies. It does **not** mean “literally no externally authored code”: OpenSSH is an open-source implementation delivered as a Windows feature. If the restriction also prohibits using OS-provided OpenSSH, there is no sensible short-path MVP: a new, independently audited SSH implementation would become the main project. **Do not write your own SSH protocol or cryptographic algorithms.** See [ADR 001](docs/ADR-001-rust-native-windows.md) for the accepted policy.

**Current implementation:** a dark resizable Win32 workspace, host CRUD, encrypted ESE inventory and saved server passwords, master-passphrase/DPAPI unlock, idle/workstation/suspend locks, a ConPTY-based built-in OpenSSH terminal with bounded common VT rendering, and four fixed read-only checks. The vault stores identity-file references, not private-key material yet. Locking hides the terminal and detaches user input; authenticated sessions and external agent identities remain independent of the vault key. See [README](README.md) for tested behavior and [the roadmap](docs/ROADMAP.md) for unfinished requirements.

### Product positioning

> “A fast, offline-first Windows command center for Linux servers: encrypted SSH identity vault, verified connections, safe one-click operations, and remote config editing — without a cloud account or a dependency-heavy app stack.”

**Proposed differentiators:** local-only by default; no account/cloud dependency; transparent cryptographic and host-key policies; strong safeguards around destructive commands; clear host inventory; integrated editor and action history. “No dependencies” by itself is a development constraint, not a strong user-facing value proposition.

---

## 2. Requirements and scope

### 2.1 MVP must-have features

1. **First-run setup and application authentication**
   - Set a strong **master passphrase**; unlock before accessing private keys or secrets.
   - Password-based unlock with rate limiting, idle timeout, and lock on workstation lock/sleep.
   - The master passphrase does not replace Linux SSH authentication.
   - No remote account, telemetry, or cloud service required.

2. **Encrypted identity vault**
   - Import and inventory OpenSSH private/public key pairs.
   - Generate **Ed25519** keys with an appropriate OpenSSH workflow; optionally support RSA-3072/4096 for legacy interoperability.
   - Encrypt private-key material **before database insertion**; associate keys with hosts, show public-key fingerprint, allow rotation and secure export.
   - Store secrets and sensitive host metadata encrypted; never write decrypted private keys into log files.

3. **Linux server inventory**
   - Save hostname/IP, port, Linux username, identity, tags, environment (dev/staging/production), and verified host-key fingerprint.
   - Connect, disconnect, group, search, and mark favorites.
   - Support nondefault SSH ports and multiple identities.

4. **SSH connection and terminal**
   - Use OS OpenSSH for protocol security, authentication, transport, and host-key verification.
   - Support interactive SSH sessions; use a separate, visible OS-hosted terminal as the earliest fallback if a native embedded terminal renderer is not ready.
   - Show connection/error state without exposing credentials.

5. **Built-in plain-text editor**
   - Open a remote file over SFTP, edit it in a simple Win32/RichEdit-based editor, compare changes, and save it back.
   - Warn on concurrent modification and preserve file permissions where supported.
   - MVP: **user-writable files only**. Privileged `/etc` editing is a later, separately hardened workflow.

6. **Safe command shortcuts**
   - Read-only: OS identity, uptime, disk/memory, service status, package search, and update availability.
   - Controlled mutations: restart a named service, `systemctl daemon-reload`, or reboot, each gated by confirmation and appropriate privileges.
   - Display target hostname, full command preview, expected privilege level, live output, exit code, and execution history.

7. **Security fundamentals**
   - Explicit SSH host-key pinning and changes warning; never automatically disable verification.
   - Allowlisted command templates with validated arguments; no unvalidated string concatenation into a remote shell.
   - Authentication, backup/recovery, encrypted vault integrity, and crash safety tested before public release.

### 2.2 Post-MVP

- SSH jump hosts (`ProxyJump`), tunnels, multiple simultaneous terminals, better terminal emulation.
- Remote file browser, syntax highlighting, diff, restore from versioned backup.
- Guided privilege escalation for a single approved action, including sudo prompt handling.
- Host health dashboards, script collections, team profiles, SSH certificate/hardware-key workflows.
- Portable encrypted backup and migration; optional device authentication (e.g., Windows Hello) after security review.
- macOS and Linux desktop clients.

### 2.3 Explicitly out of scope for v1

- Running an SSH server inside the application or installing a resident agent on Linux hosts.
- Windows, network appliances, or non-Linux managed targets.
- Shared cloud vault, team RBAC/sync, browser client, orchestration across hundreds of hosts.
- Full IDE features, remote root file editing, unattended privileged execution, unattended login while the vault is locked.
- Custom SSH cipher suites, key exchange, signature algorithms, or authentication protocols.

---

## 3. Dependency policy: define it before writing code

| Interpretation | Can the proposed MVP satisfy it? | Consequence |
|---|---|---|
| **A. No bundled third-party application frameworks or separately installed app-specific runtime libraries** | **Yes, with the approved bindings exception** | Rust + Win32 + Microsoft API bindings + Windows crypto/storage + OS-provided OpenSSH. Selected. |
| **B. No third-party binaries installed by this application** | **Yes, conditionally** | Require/check Windows OpenSSH optional feature, rather than downloading or bundling it. |
| **C. No external software components at all, including OS OpenSSH** | **Not a practical secure MVP** | Requires writing/maintaining SSHv2, authentication, KEX, SFTP and terminal functionality. High security and maintenance risk. |
| **D. No third-party code even as a development/build tool** | **Unnecessarily restrictive** | Compiler/toolchain and developer tooling become a separate compliance issue; not useful as a runtime product goal. |

**Decision for this plan:** enforce **A + B**, with Rust's standard library and Microsoft's `windows-sys`/`windows-link` bindings explicitly permitted. The owner selected this Windows-native Rust option. Document OS prerequisites prominently. OS OpenSSH is a **runtime prerequisite** even though it is not an app-bundled dependency. If it is absent, provide diagnostic instructions to enable the Windows feature, and do not silently fetch binaries. Build tools are development dependencies; inspect release imports to catch unintended runtime prerequisites.

---

## 4. Recommended technical architecture

### 4.1 Platform and language

| Layer | Windows v1 recommendation | Why / portability issue |
|---|---|---|
| Language | **Rust (2024 edition)** with Microsoft Windows API bindings | Native executable and reusable core; ownership helps application memory safety, while Windows FFI still needs reviewed unsafe boundaries. |
| UI | **Win32 + common controls**, RichEdit for text, DirectWrite/Direct2D if necessary | Available from Windows; macOS/Linux need separate UI adapters. |
| Terminal process hosting | **CreateProcessW with ConPTY** | No inherited application handles. Separate bounded input/output workers and a native GDI/common-VT renderer; advanced terminal compatibility and independent review remain. |
| SSH operations | **OS OpenSSH**: `ssh`, `sftp`, `ssh-keygen`; optional agent | Mature cryptography/protocols; versions and agent behavior must be tested. |
| Local database | **ESENT/ESE** native Windows database | Transactional storage with no bundled SQLite, but Windows-specific. |
| Vault encryption | **Windows CNG AES-256-GCM**, `BCryptGenRandom`, and PBKDF2-HMAC-SHA-256 | Built-in authenticated encryption and password-derived keys. |
| OS key binding | **DPAPI, current-user scope** | Adds Windows-account/machine binding; portable backup needs separate export format. |
| File access | Windows ACLs, atomic replacement, restricted per-user app directory | Protects ESE data files, transaction logs, exports, and temporary data. |
| Remote action framework | Hard-coded audited Linux distro/service adapters | Safe operations and consistent output; no agent on Linux. |

**Why not SQLite?** It is an excellent embedded database, but bundling it falls outside the selected Windows-native dependency policy. **Why not Qt/Electron/Tauri?** The owner chose native Windows controls. **Why ESENT?** Windows already provides it. Its contents are *not magically encrypted*: encrypt sensitive records before storage and protect all database/log/backup files with ACLs. Rust is the application language; it does not replace the OS SSH or crypto implementations.

### 4.2 Component boundaries

```text
+--------------------------------------------------------+
| Windows desktop UI                                     |
|  Host list | Terminal | Actions | Text editor | Vault  |
+------------------------------+-------------------------+
                               |
+------------------------------v-------------------------+
| Portable application core                              |
|  Host repository | Identity model | Audit | Policies    |
|  Task catalog | Linux distro profiles | Session state   |
+------------+--------------------+----------------------+
             |                    |
+------------v------------+  +----v--------------------+
| Vault & storage         |  | SSH process/agent        |
| Encrypted records       |  | adapter                   |
| Windows ESE + CNG/DPAPI |  | ssh / sftp / ssh-keygen  |
+-------------------------+  +-------------+-----------+
                                           |
                                   SSH + SFTP over TCP
                                           |
                                   Linux OpenSSH server
```

**Design for portability now:** expose narrow interfaces (`SecretStore`, `RecordStore`, `SshTransport`, `TerminalHost`, `NativeEditor`, `OsSessionEvents`). Linux command profiles and non-UI models remain independent from Windows API types. The Windows implementations are replaceable when porting to macOS/Linux.

### 4.3 Initial Rust source tree

```text
/src/core.rs              portable host models, validation, commands, bounded codec
/src/windows/ui.rs        Win32 controls and lock/session workflow
/src/windows/vault.rs     master-key lifecycle and versioned envelope
/src/windows/crypto.rs    CNG/DPAPI wrappers and secret buffers
/src/windows/storage.rs   ESE transactions and recovery
/src/windows/paths.rs     per-user directories and ACLs
/src/windows/ssh.rs       OpenSSH policy and fixed remote commands
/src/windows/process.rs   child process ownership and Windows quoting
/src/windows/pty.rs       ConPTY hosting and bounded worker lifecycle
/src/terminal.rs          bounded portable VT grid and parser
/src/windows/terminal_view.rs native terminal rendering/input
/src/windows/theme.rs     workspace palette and DPI-scaled fonts
/scripts/dev.ps1          local development and validation commands
/docs                     threat model, dependency policy, architecture, roadmap
```

Tests initially live beside the Rust modules. Add separate identity, Linux distro, remote editor, and terminal modules as their staged requirements are implemented. The first ESE schema holds one encrypted inventory envelope; per-identity, trust, and audit records follow later.

---

## 5. Security architecture: the highest-priority part

### 5.1 Threat model

Protect against: stolen laptop or copied database, accidental credential exposure, malicious/surprising host identity, command injection, replay of unsafe actions, accidental reboot, malicious server output, unauthorized local user, and tampered vault backups.

Do **not** claim to protect fully against: malware running as the same unlocked Windows user, an administrator controlling the device, a compromised Linux host, an attacker observing secrets after decryption in process memory, or malware that can use an already-authorized SSH agent. State these limits in the product's security documentation.

### 5.2 Vault format and unlock

1. Generate a random **data-encryption key (DEK)** with the OS RNG.
2. Encrypt each confidential record using **AES-256-GCM** with a **fresh unique nonce per encryption**, authenticated metadata, and an integrity tag. Include format version and record identity as authenticated associated data.
3. Derive a **key-encryption key (KEK)** from the user's master passphrase using the OS-provided **PBKDF2-HMAC-SHA-256**, with a random salt and an iteration count calibrated on supported hardware and recorded in vault metadata. PBKDF2 is a compromise imposed by the no-third-party condition; Argon2id is preferable where an audited implementation is permitted.
4. Use that KEK to wrap the DEK via authenticated encryption. Optionally **add Windows DPAPI current-user protection to the wrapped key** for device/account binding (not machine-wide DPAPI).
5. On unlock, require the master passphrase, verify the wrapped DEK authentication, and expose secrets only as needed. Never store the passphrase or a reversible plaintext passphrase field.
6. Lock automatically after inactivity or Windows workstation lock; revoke available signing capabilities when possible, clear owned in-memory secret buffers, and never promise perfect memory erasure.
7. Failed password attempts get bounded UI delays/rate limiting. **Offline database copies still permit password guessing**, so passphrase quality and KDF cost matter.
8. Implement authenticated, **portable password-protected export** independently of the DPAPI device binding; support tested restore and disaster recovery. No backdoor/reset without the original secret.

**Database design:** one or more ESENT tables with opaque **encrypted payloads** for host metadata, SSH key material, credentials, known-host decisions and task definitions; cleartext stable IDs and schema version only where needed. Encrypt before the ESE layer so transaction logs contain ciphertext, not secrets. Never reuse an AES-GCM nonce with the same key. Include backup/checkpoint files in the security review.

**Suggested logical records:** `Host`, `Identity`, `HostKeyPin`, `CommandPreset`, `ExecutionAudit`, `Setting`, `VaultHeader`. Use fixed-size non-secret identifiers and versioned record serialization. Credentials must not appear in log messages or crash reports.

### 5.3 Private-key generation and the vault-to-SSH bridge — a feasibility gate

**Default:** Ed25519 (supported by modern OpenSSH/Linux). Offer RSA-3072/4096 only where compatibility requires it. Display SHA-256 fingerprints. Key generation must use a trustworthy OS-supplied implementation and secure random source.

**Do not pretend private keys can pass directly from an encrypted database to `ssh.exe` without extra engineering.** Standard SSH tooling normally expects an identity file or an SSH agent. Treat bridging as a hard **Phase 0 proof of concept**.

Evaluate these options in this order:

| Bridge | How it works | Security caveat / decision |
|---|---|---|
| **A. Agent-backed signing** | Let `ssh.exe` use a per-user OpenSSH agent; find a supported way to load an identity without unsafe plaintext-file persistence. | Best UX if available; agent can outlive vault lock and may permit signing until key expires/removed. Must test Windows version and agent API. |
| **B. Passphrase-encrypted OpenSSH identity file** | Keep an **OpenSSH-passphrase-encrypted** key file in a restrictive per-user location; store an additionally encrypted copy in the vault. User supplies key passphrase to OpenSSH when needed. | Pragmatic first release, but a protected file **exists outside** the encrypted database; cannot claim “vault-only key storage.” |
| **C. Short-lived protected key file** | Restore key material for one session into a restricted temporary file and delete afterward. | Must disclose possibility of filesystem remnants, backup/AV indexing, crash leftovers, and temporary exposure; **do not use unencrypted temporary private keys by default**. |
| **D. Write your own agent/protocol adapter** | Implement the documented SSH agent protocol and required key formats while still using OS SSH. | Potentially avoids identity files, but introduces additional sensitive parsing/key-handling code. Needs dedicated threat review and interoperability tests. |

**Initial recommendation:** ship the MVP with an explicitly passphrase-protected key-file/agent workflow **only if the vault bridge can be made clear and safe**. If the absolute requirement is “every usable private key exists only in the encrypted DB, and never elsewhere on disk,” make a verified memory-to-agent path a **release blocker**; otherwise loosen that statement transparently.

Do not place passphrases in command-line arguments (`-N <passphrase>`), environment variables, logs, clipboard, or shared temporary files. An interactive `ssh-keygen` prompt is acceptable for an early native proof of concept. Importing an existing private-key file does not erase the user's original file.

### 5.4 SSH trust model

- Use a dedicated app-managed `known_hosts` path, or an explicit carefully documented per-user OpenSSH policy. **Never set `StrictHostKeyChecking=no`**.
- On first connect, show fingerprint and require user verification via a trusted out-of-band source. **“Accept this unknown key” alone is trust-on-first-use, not proof of identity.**
- On host-key change, block the connection and provide a manual investigate/replace workflow with audit entry.
- Support key/agent sign-in and the owner's requested saved-password option. Encrypt server passwords under the master vault data key, retain ciphertext while unlocked, and decrypt only for a selected connection. Use a private single-use OpenSSH askpass handoff; never put passwords in arguments, environment values, or plaintext files. Never automatically enable agent forwarding.
- Avoid root SSH logins as the default and do not silently disable server security settings.
- Pin the executable path to the Windows OpenSSH binary, validate the local feature/version, and safely construct Win32 child-process command lines and handles.

### 5.5 Linux commands and safe execution

Use a **data-driven but non-user-editable audited catalog** of commands for v1. Each action has: `id`, distro compatibility, parameters and validators, preview, privilege requirement, impact tier, execution timeout, and output parser.

| Action | Example Linux command | Default classification |
|---|---|---|
| System identity | `uname -a`; `cat /etc/os-release` | Read-only |
| Uptime | `uptime` | Read-only |
| Disk usage | `df -h` | Read-only |
| RAM usage | `free -h` | Read-only |
| List units | `systemctl list-units --type=service --all` | Read-only |
| Check status | `systemctl status <validated-service>` | Read-only |
| Check available updates (Debian/Ubuntu) | `apt list --upgradable` | Read-only; package metadata may be stale |
| Search package (Debian/Ubuntu) | `apt-cache search <validated-query>` | Read-only; package-cache availability varies |
| Search package (Fedora/RHEL) | `dnf search <validated-query>` | Read-only |
| Reload systemd manager | `sudo systemctl daemon-reload` | Changes manager state; confirmation |
| Reload one service | `sudo systemctl reload <validated-service>` | Mutating; service must support reload |
| Restart one service | `sudo systemctl restart <validated-service>` | Potential outage; typed confirmation for production |
| Reboot | `sudo systemctl reboot` | Destructive/disruptive; typed hostname + impact warning |

Distinguish **`daemon-reload`** (reloads systemd unit definitions) from **`reload service`** (asks one service to reload its configuration). Also distinguish **checking** updates from **installing** them; upgrade/install stays out of the MVP.

**Injection controls:** assemble only known templates; validate service/package arguments against a conservative grammar and length limit; treat remote command strings as untrusted because SSH execution eventually goes through a remote shell; do not allow arbitrary user-provided tokens to become flags, operators, expansions, or redirections. Spawn the local SSH binary directly; do not invoke `cmd.exe /c` or PowerShell around it.

**Safety UX:** read-only shortcuts may run without confirmation. Mutating shortcuts show exact hostname/user/command, environment color/label, elevated privilege requirement, and a deliberate confirm action. Production reboot and restart require typing the host name. Clearly report timeout, exit status, and whether the SSH disconnect is expected after reboot. An audit log is local and encrypted; redact secrets and sensitive stdout as appropriate.

### 5.6 Remote file editing

- Fetch file through SFTP to a **restricted user-only staging path** (or memory-based path if supported by the chosen bridge). Never stage private keys or other specially protected secrets as ordinary text.
- Keep the original file hash and mtime; on save, check if remote content changed since opening; show conflict options instead of overwriting silently.
- Upload to a remote staging file, preserve permissions/ownership when permitted, create optional backup, and rename/replace **only where the server supports the needed semantics**.
- Verify post-save content and report any partial failures. Avoid assuming SFTP writes are universally atomic or that `sudo` works within SFTP.
- For privileged configs, later use an explicit audited workflow: upload a staging file with ordinary privileges, validate it, then request a carefully scoped `sudo install`/service reload action. Do not automatically run as root.
- RichEdit provides a basic editor; grammar-aware syntax highlighting, large-file streaming, search/replace and diffs are future work.

---

## 6. Development stages and exit gates

**Effort estimate:** approximately **16–26 calendar weeks** for a strong native-Windows engineer plus part-time UI/testing/security assistance, **assuming the agent/vault and terminal spikes succeed**. For a solo developer new to Win32, SSH internals, or security engineering, a **6–12+ month** schedule is more realistic. These are planning estimates, not fixed commitments.

| Phase | Approx. duration | Main deliverables | Exit criteria |
|---|---:|---|---|
| **0 — Feasibility and threat model** | Weeks 1–3 | Product scope; threat model; verify Windows OpenSSH install/version; Ed25519 generation; encrypted-vault-to-SSH bridge spike; ConPTY/terminal test; ESE proof of concept | Authenticate to a test Linux VM with a generated key and explain **exactly** where all key material resides; reliable SSH host-key verification; go/no-go on no-deps constraint |
| **1 — Windows skeleton and host inventory** | Weeks 4–6 | Win32 shell, navigation, host CRUD, validation, settings, storage abstraction and ESE schema | Add/edit/delete/search 50 hosts; restart/crash does not corrupt inventory; user-scoped ACLs |
| **2 — Encrypted vault and auth** | Weeks 7–10 | Master-passphrase setup/unlock, CNG encryption, DPAPI wrapping, key import/generation, vault backup/restore, auto-lock | Wrong passphrase fails; modified ciphertext fails authentication; keys never stored plaintext in ESE/logs; restore validated on a clean test setup |
| **3 — SSH and terminal experience** | Weeks 11–14 | Connect/disconnect/reconnect, identity association, host-key prompts, session list; ConPTY-based embedded terminal or documented OS-terminal fallback | Real sessions to supported Linux VMs; prompt/resize/UTF-8 and disconnection tests pass; no host-key verification bypass |
| **4 — Safe Linux operations** | Weeks 15–17 | Distro probe, safe shortcut catalog, output/exit-code capture, confirmations, command audit | No shell injection in fuzzed parameter inputs; read-only/mutating policy enforced; reboot flow is explicit and recoverable |
| **5 — SFTP and editor** | Weeks 18–20 | File navigation/open/edit/save, conflict handling, backups, encoding/line endings support | Edits survive round-trip; save conflict detected; interrupted transfer does not silently corrupt original file |
| **6 — Hardening and beta release** | Weeks 21–26 | Installer/uninstaller, diagnostics, docs, reproducible release build, test matrix, independent security review | Go/no-go security checklist complete; backup recovery demonstrated; severity-critical issues closed; signed binary if distributing publicly |

**Schedule note:** phases can overlap with multiple engineers. **Do not skip Phase 0** or make the security release gate optional. If the terminal renderer takes longer, use a clearly marked Windows console fallback for v0.1 while finishing an integrated display.

### Phase 0: concrete first 10 engineering tasks

- [x] Publish the dependency definition (A+B plus approved Microsoft Rust bindings) as [ADR 001](docs/ADR-001-rust-native-windows.md).
- [ ] Confirm which Windows versions include/install OpenSSH Client and collect `ssh -V` on test machines.
- [ ] Create two disposable Linux SSH test VMs (Ubuntu and Debian) with known host-key fingerprints.
- [ ] Generate an Ed25519 key through OS `ssh-keygen` without exposing the passphrase on a command line.
- [ ] Prove how the app opens an SSH session using a vault-managed identity; record on-disk/in-memory/agent exposure.
- [ ] Run an SSH session inside ConPTY and identify the minimum VT sequences/terminal interactions needed.
- [x] Create a Win32/ESE DB containing encrypted test records; force process termination after commit and during an uncommitted transaction, then recover.
- [ ] Test AES-GCM tamper rejection and PBKDF2 unlock on a slow supported device.
- [ ] Attempt a first-connection MITM/changed-host-key test; demonstrate it blocks.
- [ ] Review findings; update product scope, threat model, schedule, and go/no-go decision.

### Proposed first shipping slice (v0.1)

A small beta with **unlock → saved host → verified SSH connection → key-backed terminal → read-only shortcuts**, followed by encrypted backup and key management polish. Remote editing and disruptive actions come after those foundations pass security testing.

---

## 7. User journeys and UX blueprint

**Main navigation:** `Servers | Sessions | Commands | Files | Keys | Settings`.

1. **Onboarding:** create master passphrase → set auto-lock period → detect OpenSSH Client → generate/import key → add server → verify host fingerprint → test connect.
2. **Daily server operation:** choose host → see status and last connection → start terminal or choose `Disk usage`, `Services`, `Updates`, `Packages` → view output and audit.
3. **Risky action:** choose `Reboot` → show production warning and exact destination → type hostname → optionally require master-passphrase re-authentication → run → show expected disconnect and a reconnection option.
4. **Editing:** select server/file → fetch and display → edit → preview diff → detect remote conflicts → back up and save → optional validated service reload.
5. **Recovering a machine:** install app on replacement Windows device → import encrypted portable backup → enter master passphrase → re-establish Windows device binding and host trust policy intentionally.

**UX principle:** put host identity, effective Linux username, current privilege level, and production/staging classification beside every privileged action. No hidden operations.

---

## 8. Verification, testing and release requirements

### Functional matrix

- Windows 11 x64 primary; Windows 11 ARM64 if relevant; Windows 10 only after OpenSSH/API verification.
- Ubuntu LTS and current Debian as Tier 1; Fedora/RHEL family after package adapter and sudo testing.
- SSH key auth, multiple ports and identities, inaccessible host, password-protected key, key rotation, host-key replacement, lock/sleep/resume.
- Files: UTF-8, CRLF/LF, permission denied, zero-length, large file, concurrent change, aborted upload.
- Commands: correct exit codes, timeout, `sudo` refusal, absent `systemctl`, server reboot, transient disconnect, distro mismatch.

### Security tests / release blockers

- [ ] Independent review of vault encryption, key lifecycle and export/import design.
- [ ] AES-GCM tamper and nonce uniqueness tests; KDF metadata/version upgrade tests.
- [ ] No passphrases/private keys in process arguments, temp plaintext files by default, stdout logs, or crash diagnostics.
- [ ] If temporary private-key files are used, their residual-data risk is explicitly documented and accepted (otherwise block release).
- [ ] Database, transaction logs, backup and staging directories protected with correct Windows ACLs.
- [ ] Host-key mismatch is a hard failure; no implicit acceptance of new host identities.
- [ ] Command argument mutation/fuzzing, path traversal, malicious server-provided terminal sequences and SFTP file names tested.
- [ ] User-visible confirmation for disruptive operations; no accidental execution on wrong selected host.
- [ ] Complete offline install, no account registration, no telemetry by default, no automatic third-party downloads.
- [ ] Encrypted backup/restore is proven on a separate machine; loss-of-password recovery limitations disclosed.
- [ ] Code signing and secure update design documented if publicly distributing builds.

### Candidate outcome metrics

- Five Linux hosts can be imported, organized, connected to, and safely administered without leaving the app for routine checks.
- No unencrypted **private SSH keys in the application database** (verify database and transaction logs).
- Zero critical/high issues from security review before public beta.
- All destructive actions are attributed to a specific host, actor/local session, time and command template.
- Document every system dependency and demonstrate launch with networking disabled (except SSH connection itself).

---

## 9. Competitor landscape — existing solutions

**Yes. The proposed feature combination already exists across several products.** The opportunity is to deliver a simpler **offline-first, no-cloud-account, Windows-native** workflow with stronger Linux-operation safeguards and a transparent vault design. Do not assume that key management, terminal tabs, one-click commands, or a remote editor alone are novel.

| Product | Relevant features verified from official project/site | Position relative to this proposal |
|---|---|---|
| **Termius** | Windows/macOS/Linux clients, host inventory, SSH keychain/vault, snippets, SFTP, encrypted synchronization, hardware-key options. [Official site](https://termius.com/) · [Vault](https://termius.com/vault) | Strong overlap in **key vault + cross-platform SSH**; differentiate through local-only administration workflows. |
| **MobaXterm** | Windows SSH sessions, SFTP file browser, embedded text editor, macros, master-password-protected saved credentials. [Official features](https://mobaxterm.mobatek.net/features.html) | **Very close** to terminal + remote editor + automation concept; a good Windows UX benchmark. |
| **Royal TS** | Remote connection manager, SSH, credential management, command tasks and key-sequence tasks. [Official features](https://www.royalapps.com/ts/win/features) | Strong overlap in managed connections and shortcuts; broader protocols and administrative focus. |
| **Devolutions Remote Desktop Manager** | Centralized connections, credential vaults, SSH, access/role workflows and auditing. [Official site](https://devolutions.net/remote-desktop-manager/) | Feature-rich enterprise alternative; proposed app should be lighter and easier for individuals/small teams. |
| **WindTerm** | Cross-platform SSH/SFTP terminal, session tree, agent support, local credential protections, command features. [Project repository](https://github.com/kingToolbox/WindTerm) | Strong terminal and local-first benchmark; “no third-party dependencies” and safety UX are possible points of distinction, not yet proof of superiority. |

**Research caveat:** exact subscription plans, feature restrictions, supported editions and vendor claims can change. Verify them immediately before product pricing or marketing decisions. Competitor sites are feature claims, not independent security audits.

### Suggested differentiation to validate with prospective users

- **Safety-first action catalog:** contextual commands, validation, preview, typed hostname confirmation, clear distinction between reboot/restart/reload.
- **Local-only identity management:** no compulsory cloud account, transparent offline encrypted backup, explicit host-key verification.
- **Built for Linux day-to-day operations:** package/distribution awareness, service status, safe config editing, permission-aware saves.
- **Small trustworthy installation:** native UI, known OS prerequisites, no embedded browser engine or app-bundled plugin system.

Interview **8–12 Linux developers, sysadmins, and small-team operators** to validate whether these matter enough to replace current tools. Collect their top five repeated tasks and their biggest pain points before expanding scope.

---

## 10. Roadmap toward macOS and Linux clients

**Do not promise a “compile once” port.** Windows-native Win32, DPAPI and ESENT have no identical implementations on macOS or Linux.

1. **Before Windows MVP:** keep portable models/command policies independent of UI and Windows APIs; define a versioned, OS-neutral encrypted export format and interfaces.
2. **After Windows security/stability:** port to **macOS** with native Cocoa/AppKit UI and Apple Keychain/Security/Crypto APIs where available. Use the system SSH/OpenSSH implementation; define a replacement for ESE.
3. **Then Linux desktop:** choose target distros, graphics stack and key storage policy first. Linux does **not** provide one universally present desktop GUI, database and cryptographic API equivalent to Win32 + ESENT + CNG. Reassess whether strictly no third-party runtime dependencies is still sensible.
4. Keep Linux **managed servers** agentless from day one. Later desktop clients must not be confused with the Linux server targets.

**Important trade-off:** a hard ban on *all* third-party libraries will **significantly increase** multi-OS UI, terminal and storage maintenance. A policy exception for a small, audited, pinned and reproducibly built cryptographic/SSH stack might eventually provide **better security** than reimplementing missing platform services.

---

## 11. Risks and mitigation register

| Risk | Likelihood / impact | Mitigation / decision gate |
|---|---|---|
| Vault-managed key cannot be safely passed to OS SSH without files | High / high | Phase 0 bridge spike; clearly state supported storage model; no misleading “never on disk” claim. |
| Building an embedded terminal with no UI library consumes roadmap | High / medium | Start with OS-hosted terminal fallback, prove ConPTY, implement VT renderer incrementally. |
| Windows-only storage makes later portability expensive | High / medium | `RecordStore` abstraction, portable encrypted export, platform-neutral schemas. |
| Native application auth gives false sense of protection | Medium / high | Make it a real encryption unlock; explain same-user malware limitation and Windows-account binding. |
| Malicious input leads to shell injection or wrong-host execution | Medium / critical | Only allowlisted templates; validated arguments; explicit target and impact confirmation. |
| Remote editor corrupts config or silently changes permissions | Medium / high | Staging, hash conflict check, backup, permission check and verify-on-save. |
| Misconfigured sudo creates escalation/lockout | Medium / high | No unattended root by default; phased privilege model, no sudo password persistence. |
| ESE logs or export leaks sensitive metadata | Medium / high | Encrypt payload before ESE, ACL everything, inspect real log/backup artifacts. |
| Low differentiation in a mature product market | High / medium | User interviews; ship narrowly focused safe Linux workflows rather than clone a general terminal. |

---

## 12. Decisions to lock down now

1. **Third-party meaning — decided:** Windows-native Rust, permitting Microsoft's API bindings and Rust standard library, while avoiding bundled application frameworks and app-installed OpenSSH binaries. See ADR 001.
2. **Security contract:** decide whether only *encrypted-at-rest database storage* is required, or **no separate key file ever**, including passphrase-encrypted OpenSSH files. This materially changes complexity.
3. **Initial customer:** individual developer/small infrastructure operator, not enterprise multi-user privileged-access management.
4. **Initial Linux scope:** Ubuntu/Debian + systemd + apt, key/agent and encrypted saved-password OpenSSH login, standard SFTP.
5. **MVP terminal expectation:** OS-hosted terminal acceptable for earliest internal beta; full integrated renderer required before marketing as a fully self-contained terminal.
6. **Cloud position:** strictly offline/local-first for initial release.

### Immediate next steps

- [x] Create a repository, [threat model](docs/THREAT_MODEL.md), [dependency policy](docs/ADR-001-rust-native-windows.md), and [feature/specification checklist](docs/ROADMAP.md).
- [ ] Implement the five-part **Phase 0 prototype**: `ssh-keygen` → import/storage → vault unlock → agent/key bridge → verified SSH login.
- [ ] In parallel, test ESE + AES-GCM and a ConPTY terminal prototype.
- [ ] Select the final v0.1 scope only after those tests, then execute Phase 1.

---

## 13. Primary references

**OS/security/standards**

- Microsoft: [Rust for Windows API bindings](https://github.com/microsoft/windows-rs).
- Rust: [Windows MSVC prerequisites](https://rust-lang.github.io/rustup/installation/windows-msvc.html).

1. Microsoft: [OpenSSH for Windows overview](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-overview).
2. Microsoft: [OpenSSH key-based authentication](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement).
3. Microsoft: [Cryptography API: Next Generation](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal).
4. Microsoft: [BCryptDeriveKeyPBKDF2](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptderivekeypbkdf2).
5. Microsoft: [CryptProtectData (DPAPI)](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata).
6. Microsoft: [ESENT/ESE database and security considerations](https://learn.microsoft.com/en-us/windows/win32/extensible-storage-engine/about-extensible-storage-engine).
7. Microsoft: [CreatePseudoConsole (ConPTY)](https://learn.microsoft.com/en-us/windows/console/createpseudoconsole).
8. IETF: [RFC 8709 — Ed25519 in SSH](https://www.rfc-editor.org/rfc/rfc8709.html).
9. IETF: [RFC 9987 — SSH Agent Protocol](https://datatracker.ietf.org/doc/html/rfc9987).
10. OpenSSH: [Agent restriction design](https://www.openssh.org/agent-restrict.html).

**Competitors:** [Termius](https://termius.com/), [MobaXterm](https://mobaxterm.mobatek.net/features.html), [Royal TS](https://www.royalapps.com/ts/win/features), [Devolutions RDM](https://devolutions.net/remote-desktop-manager/), [WindTerm project](https://github.com/kingToolbox/WindTerm).

---

*This is an implementation plan, not a formal security certification. Any publicly distributed app that holds production SSH private keys should receive an independent code and threat-model review before release.*
