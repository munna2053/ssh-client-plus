# Publishing a Windows release

The [Release workflow](../.github/workflows/release.yml) builds a Windows x64 portable ZIP with the pinned Rust 1.90 MSVC toolchain on GitHub's `windows-2022` runner. It checks formatting, runs Clippy and the test suite, builds the optimized executable, and runs its disposable UI smoke test. The MSVC runtime is statically linked into the executable.

## First setup

Commit and push the workflow, packaging script, and accompanying documentation to the repository's default branch. In the repository's **Actions** tab, ensure GitHub Actions is enabled. The workflow uses the automatic `GITHUB_TOKEN`; no personal access token or new repository secret is needed. If an organization policy restricts workflow write access or allowed actions, that policy must permit the publish job's `contents: write` permission and the pinned official GitHub actions.

Before publishing, select **Actions > Release > Run workflow** and choose the default branch. A branch run builds and uploads a `windows-x64-release` Actions artifact for review, without creating a GitHub Release. This is also the first validation of the complete MSVC build on a clean hosted Windows machine.

## Publish a version

1. Set the package version in `Cargo.toml` and update the root package's version in `Cargo.lock`. The current version is `0.1.0`, so the first tag can be `v0.1.0`.
2. Commit and push the intended release commit, including the workflow files. Make sure your working tree is clean.
3. Create an annotated tag on that commit and push only that tag:

   ```powershell
   git tag -a v0.1.0 -m "SentinelSSH v0.1.0"
   git push origin v0.1.0
   ```

4. Watch **Actions > Release**. The workflow refuses a tag that does not exactly match `v` plus the Cargo package version.
5. After all checks pass, the publish job creates a visible [GitHub Release](https://github.com/munna2053/ssh-client-plus/releases) with generated change notes and these assets:

   - `sentinel-ssh-0.1.0-windows-x64.zip`
   - `sentinel-ssh-0.1.0-windows-x64.zip.sha256`

The release appears in the repository's **Releases** section and README download link. If the repository's right-hand sidebar does not show Releases, use the **About** settings gear to enable that section. Users must download the application ZIP under **Assets**; GitHub's automatically generated **Source code** archives do not contain a built executable. Downloads from a private repository remain restricted to people with repository access.

Versions such as `0.2.0-rc.1` must appear in both Cargo files and use a matching `v0.2.0-rc.1` tag. These are published with GitHub's **Pre-release** label and are not marked Latest. Ordinary version tags publish regular releases. Manual workflow runs on a tag also publish that tag; branch runs only produce Actions artifacts.

Publishing runs only after the build job succeeds. A failed build publishes nothing. Fix build failures on a new commit and use a new version/tag; do not move published tags. If a run failed only during publication and no release was created, re-run its failed jobs. An existing release is not overwritten by the workflow.

## Package locally

After a normal MSVC release build:

```powershell
cargo build --release --locked --target x86_64-pc-windows-msvc
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\package-release.ps1 -Version 0.1.0
```

For the project's local GNU/LLVM development build, supply the executable explicitly:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\package-release.ps1 -Version 0.1.0 -Executable .\target\slint\release\sentinel-ssh.exe
```

Output lives in `target\release-assets`. The ZIP contains only the executable, user README, MIT license, and threat model. It never packages the application's database, private keys, `.scratch`, or `.tools`. The script also writes the checksum file and the release-notes introduction used by the publish job.

Check a downloaded ZIP in PowerShell by comparing the hash with the first field of its `.sha256` file:

```powershell
Get-FileHash .\sentinel-ssh-0.1.0-windows-x64.zip -Algorithm SHA256
Get-Content .\sentinel-ssh-0.1.0-windows-x64.zip.sha256
```

The current package is unsigned and has no installer or automatic updater. Build automation does not close the remaining security and live-host validation gates described in [the threat model](THREAT_MODEL.md).
