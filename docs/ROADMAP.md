# Rust implementation checklist

Updated: 10 October 2026. The full scope remains in [the engineering plan](../secure_ssh_server_manager_project_plan.md).

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
- [x] System/uptime/disk/memory checks with target/command confirmation and console output.
- [x] Wrong-password, tamper, invalid-input, native UI, encrypted-artifact, and crash-recovery tests.
- [x] Local GNU/LLVM release build; inspect imported DLLs.

## Next: complete the feasibility gate

- [ ] Build and run with the complete MSVC toolchain and Windows SDK.
- [ ] Validate login to disposable Ubuntu/Debian hosts using encrypted key files, an agent, and saved server passwords.
- [ ] Validate console keyboard input, passphrase prompts, resize, UTF-8, and disconnection.
- [ ] Demonstrate first-use fingerprint verification and changed-key hard failure against real hosts.
- [ ] Prove the encrypted-vault-to-key/agent bridge and document where every usable private key exists.
- [ ] Calibrate KDF cost on supported hardware and review secret/FFI/path ownership.
- [ ] Run an independent review before treating the vault as suitable for production data.

## Complete the first shipping slice

- [ ] Portable authenticated encrypted backup/restore and recovery tests.
- [ ] Passphrase change, schema/KDF upgrades, and account/device migration.
- [ ] Import/generate keys, inspect public fingerprints, associate identities, rotate, export.
- [ ] Define agent lifetime/signing revocation behavior on lock.
- [ ] Host tags, environments, search, favorites, and connection/session UI.
- [ ] Host-key inspection and explicit replacement workflow.
- [ ] Execution history, captured error details, timeout/cancellation, and distro probes.

## Later staged features

- [ ] ConPTY with a reviewed terminal renderer and hostile-output tests.
- [ ] Package/service adapters and guarded administrative actions.
- [ ] SFTP browse/open/save with conflict checks, backups, and permission preservation.
- [ ] RichEdit remote-text editor and diff workflow.
- [ ] Installer, signing, secure updates, and broader platform/security testing.
- [ ] Separate macOS and Linux platform adapters after Windows stability.
