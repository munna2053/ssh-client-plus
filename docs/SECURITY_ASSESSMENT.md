# Security assessment — SentinelSSH

Assessment date: 11 October 2026. Reviewed commit: `fd78bd335f4fa57b336b15c502444edbfc6a113b` (initial working tree clean).

Two findings were confirmed: one Medium and one Low. No Critical or High vulnerability was confirmed within this review. The preview should retain its existing release gates, particularly live SSH authentication/host-key testing and filesystem/FFI review. This assessment does not establish production readiness.

The review covered the Rust source, vault and credential lifecycle, Windows permissions and process launch, SSH arguments, terminal parser and clipboard handling, storage, development scripts, dependency lockfile, and existing tests. It used source inspection, local disposable fixtures, and current primary-source advisory checks. Application source was not changed. No real vault was opened and no external SSH server was contacted.

| ID | Severity | Finding | Evidence |
| --- | --- | --- | --- |
| F-01 | Medium | Clipboard escape sequences can terminate bracketed paste early | Exact paste method reproduced in an isolated harness; embedded terminator survives |
| F-02 | Low | Unicode secret conversion can reallocate plaintext before clearing ownership | Allocator instrumentation observed a plaintext-bearing reallocation |

1. **F-01 — Sanitize clipboard control sequences before framing a paste.**

   Locations: `src/windows/terminal_view.rs:289` (paste normalization and framing), `src/windows/terminal_view.rs:112` (input queuing), and `src/windows/terminal_view.rs:679` (clipboard input).

   The paste handler changes line endings and wraps text in `ESC[200~` / `ESC[201~` when bracketed paste is enabled. It does not reject or remove an embedded ESC character or paste terminator. The outer framing therefore does not prevent attacker-controlled clipboard content from ending the paste early. These delimiters are defined by the [xterm bracketed-paste protocol](https://invisible-island.net/xterm/ctlseqs/ctlseqs.html#h2-Bracketed-Paste-Mode).

   **Prerequisites and impact:** A user copies attacker-controlled text, for example from a webpage, and pastes it into an authenticated remote shell. A shell that interprets the first terminator as the end of pasted input can process subsequent carriage returns as Enter presses, executing commands with that SSH account's privileges. This requires user interaction and a compatible receiving shell. It is not a demonstrated local Windows code-execution vulnerability.

   **Reproduction:** Enable bracketed paste with `ESC[?2004h`. Supply the following disposable clipboard payload, where escapes below represent actual bytes:

   ```text
   echo harmless\x1b[201~\necho AUDIT_MARKER\n
   ```

   The handler emits:

   ```text
   \x1b[200~echo harmless\x1b[201~\recho AUDIT_MARKER\r\x1b[201~
   ```

   The probe extracted the current `View::paste` body verbatim, supplied fixture clipboard text, and captured its `send` output. It found two end markers and confirmed command text plus carriage returns after the first marker. It did not modify the real clipboard or execute the text in a remote shell. The byte-framing defect is reproduced; the end-to-end shell consequence should be validated against supported shells.

   **Remediation:** Reject or safely filter embedded ESC and other disallowed terminal input controls before sending clipboard text; account for alternate control encodings supported by the receiving stack. Offer a preview/confirmation for multiline or control-bearing paste, especially when bracketed paste is disabled. Keep ordinary Unicode text and intended tab/newline behavior intact. Queue a paste as a complete bounded operation so backpressure cannot silently discard its closing delimiter.

   **Acceptance checks:** Test embedded start/end delimiters, control characters, CR/LF/CRLF, Unicode, disabled bracketed paste, maximum size, and input-queue saturation. On disposable supported Linux shells, the marker command must not execute merely because malicious text was pasted.

2. **F-02 — Take clearing ownership before converting Unicode secrets.**

   Locations: `src/windows/ui.rs:753` and `src/windows/terminal_view.rs:701` (UTF-16 conversion); `src/windows/crypto.rs:41` (secret destructor).

   Both password input and clipboard text use `String::from_utf16(...).map(|text| Secret(text.into_bytes()))`. The temporary String can grow while converting UTF-16 to UTF-8. Non-ASCII characters can require more UTF-8 bytes than UTF-16 code units. A growth operation can release an earlier plaintext allocation before the final allocation is placed inside `Secret`; the destructor cannot wipe that earlier allocation. Conversion errors can also drop a partially constructed ordinary String outside clearing ownership.

   **Prerequisites and impact:** This matters when memory, heap remnants, paging, or dumps become accessible. It can extend the lifetime of master-passphrase or server-password fragments after field clearing and vault locking. It does not independently grant memory access or bypass vault encryption. Severity is Low because the threat model already excludes same-user malware and acknowledges best-effort clearing, but these application-created intermediate copies are avoidable.

   **Reproduction:** The local probe instrumented allocator reallocations only during the same conversion expression, using a disposable string beginning with `AUDIT-FIXTURE-` followed by Bengali text, repeated 40 times. It observed one reallocation whose initialized prefix still contained the fixture plaintext before `Secret` ownership. This demonstrates the clearing gap, not recovery of a real password from freed memory; whether a particular reallocation moves is allocator-dependent.

   **Remediation:** Decode into a clearing buffer owned from the beginning, with capacity calculated before plaintext is written. Wipe partial results on every error. Review shrinking operations as well: paste normalization uses `retain_mut`, whereas `Secret::drop` clears only the current length, so the design should explicitly erase initialized bytes discarded from the logical buffer. Avoid promising removal of copies held by Windows controls, OpenSSH, the OS, or dumps.

   **Acceptance checks:** Instrument ASCII, Bengali, supplementary characters, invalid UTF-16, and CRLF normalization using disposable fixtures. Verify that conversion does not release an unwiped plaintext allocation and that discarded initialized bytes are cleared.

The following are **hardening and validation gaps**, not additional confirmed vulnerabilities:

- **OpenSSH runtime maintenance:** `src/windows/ssh.rs:116` checks executable presence, without a supported-version or servicing policy. This machine reports `OpenSSH_for_Windows_9.5p2`, file version `9.5.6.2`. Inventory the actual serviced Windows binary and track supported security updates. Do not infer vulnerability from the upstream version string alone because vendor fixes can be backported. The [upstream security page](https://www.openssh.org/security.html) documents client issues including the 9.5–9.7 keystroke-timing flaw and the conditional VerifyHostKeyDNS issue. The application bypasses personal config and does not enable VerifyHostKeyDNS, so the latter was not classified as an exploitable finding here. Windows-specific release information is available from [Microsoft's Win32-OpenSSH project](https://github.com/PowerShell/Win32-OpenSSH/releases).
- **Live authentication and trust tests:** Existing tests cover helper delivery and a refused loopback connection, but do not establish successful system-OpenSSH saved-password login, first-use acceptance/rejection, changed-key failure before credential release, key passphrases, or agent interoperability. Exercise these with disposable Linux servers and verify which party receives credentials, especially for mismatched keys.
- **Terminal work budgeting:** `src/windows/ui.rs:1261` processes output on the same thread as lock/timer events. One optimized local model probe processing sixteen 8,192-byte erase-sequence packets at 240 × 120 took approximately 0.75–0.77 seconds. Memory bounds alone do not ensure prompt event handling. Add a time/work budget and measure lock responsiveness under hostile output. This was a direct parser benchmark; ConPTY may normalize/coalesce sequences, so an end-to-end remote denial of service was not demonstrated.
- **Filesystem object validation:** Directory and trust-file reparse checks exist, but validation uses paths rather than held handles, and `src/windows/storage.rs:86` opens the database without independently validating the final database object. Ancestor races, pre-existing explicit file ACLs, links, and ownership need controlled multi-user tests. No cross-user escape was established; the private directory ACL materially limits the attacker prerequisites.
- **Secret retention policy:** Authenticated sessions and terminal history intentionally survive vault lock. This is documented behavior, not a newly discovered lock bypass. Consider whether users need a separate disconnect-and-clear action and a defined policy for clipboard contents they copied manually.

Validation performed:

| Check | Result |
| --- | --- |
| `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\dev.ps1 -Action test -Portable -Offline` | Passed: 25 library tests, 1 embedded-terminal integration test, 3 password-handoff integration tests |
| `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\dev.ps1 -Action clippy -Offline` | Passed with configured warnings denied |
| Isolated optimized probe | Confirmed paste framing and Unicode conversion findings; measured parser work |
| Tracked-source credential-pattern scan | No matches for the selected private-key/AWS/GitHub/OpenAI token patterns; not an exhaustive secret or Git-history audit |
| Dependency inspection | Lockfile contains `windows-sys 0.61.2` and `windows-link 0.2.1`; no matching entries found in the [RustSec advisory index](https://rustsec.org/advisories/) checked during this review |

The ad hoc probe is retained locally at `.scratch/security-review/probe.rs` with its executable; `.scratch` is ignored by Git. Its clipboard and send functions are fixture adapters around the extracted paste method. No package vulnerability scanner was installed or run; the advisory check was manual and does not cover Windows system DLLs, the Rust toolchain, or establish the servicing status of OpenSSH.

Existing strengths include CNG AES-256-GCM with authenticated metadata, bounded vault decoding, PBKDF2-SHA256 with 600,000 iterations, account-bound DPAPI, separately encrypted saved passwords, volatile clearing of owned live secret bytes, explicit system OpenSSH selection, argument validation and Windows quoting, disabled agent forwarding, a dedicated trust file, and a single-use credential broker with cancellation and process checks. Passing tests support these controls but do not replace live SSH testing, fuzzing, or an independent native-code audit.

Fix F-01 first, then close F-02's buffer-lifecycle gaps and the live SSH release tests. Reassess any implementation changes before treating these findings as resolved.
