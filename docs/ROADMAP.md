# Rust implementation checklist

Updated: 13 October 2026. The full scope remains in [the engineering plan](../secure_ssh_server_manager_project_plan.md).

## Implemented preview

- [x] Rust crate with pinned Microsoft Windows bindings and native Win32 controls.
- [x] Bounded host validation/serialization and encrypted inventory create/read/update/delete.
- [x] Password setup/unlock, independent data key, CNG AES-GCM, PBKDF2, and current-user DPAPI.
- [x] Current-user data-directory ACLs; ESE data/logs in the protected directory.
- [x] Manual and ten-minute application idle lock; workstation-lock/suspend messages.
- [x] Explicit system OpenSSH path, shell-free native process launch, and Windows argument quoting.
- [x] Dedicated host trust file, first-use confirmation, key/agent login, and disabled forwarding.
- [x] Saved-password login with separate vault-key encryption, on-demand decryption, and single-use private askpass handoff.
- [x] Legacy inventory upgrade, encrypted-password edit/reopen tests, helper delivery/cancellation and caller validation.
- [x] System/uptime/disk/memory shortcuts dropdown that inserts commands into the active terminal for editing and explicit Enter to run.
- [x] Wrong-password, tamper, invalid-input, native UI, encrypted-artifact, and crash-recovery tests.
- [x] Dark resizable workspace, server-card Connect/Edit controls, and a separate server editor.
- [x] Slint Windows frontend with hover/press/focus animations, native terminal hosting, dark scrollbars, and disposable UI preview/smoke tests.
- [x] Independent SSH session tabs, per-session terminal/history, tab paging/closing, and active-tab shortcut routing.
- [x] ConPTY terminal with common VT rendering, keyboard, colours, copy/paste, resize, bounded history, and explicit disconnect.
- [x] Console-attachment/input/resize/final-output/cleanup tests and hostile-output parser tests.
- [x] Local GNU/LLVM release build; inspect imported DLLs.

## Next: complete the feasibility gate

- [ ] Build and run with the complete MSVC toolchain and Windows SDK.
- [ ] Validate login to disposable Ubuntu/Debian hosts using encrypted key files, an agent, and saved server passwords.
- [ ] Validate embedded-terminal keyboard input, passphrase prompts, resize, Unicode, full-screen Linux tools, and disconnection against live hosts.
- [ ] Demonstrate first-use fingerprint verification and changed-key hard failure against real hosts.
- [ ] Prove the encrypted-vault-to-key/agent bridge and document where every usable private key exists.
- [ ] Calibrate KDF cost on supported hardware and review secret/FFI/path ownership.
- [ ] Run an independent review before treating the vault as suitable for production data.

## Complete the first shipping slice

- [ ] Portable authenticated encrypted backup/restore and recovery tests.
- [ ] Passphrase change, schema/KDF upgrades, and account/device migration.
- [x] Generate Ed25519 OpenSSH key pairs from the server editor, save private files with per-user ACLs, and display/copy the public key. Optional passphrases encrypt generated files; the vault stores the identity path.
- [ ] Import keys into the encrypted vault, inspect public fingerprints, rotate, export.
- [ ] Define agent lifetime/signing revocation behavior on lock.
- [ ] Host tags, environments, search, favorites, and connection/session UI.
- [ ] Host-key inspection and explicit replacement workflow.
- [ ] Execution history, captured error details, timeout/cancellation, and distro probes.

## Later staged features

- [ ] Independent terminal renderer review, advanced terminal compatibility, and mouse reporting.
- [ ] Package/service adapters and guarded administrative actions.
- [ ] SFTP browse/open/save with conflict checks, backups, and permission preservation.
- [ ] RichEdit remote-text editor and diff workflow.
- [ ] Installer, signing, secure updates, and broader platform/security testing.
- [ ] Separate macOS and Linux platform adapters after Windows stability.
