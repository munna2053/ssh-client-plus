# Publishing a Windows release

Pushing a `v*` tag runs the [Release workflow](../.github/workflows/release.yml) on GitHub. It checks formatting, runs Clippy and the tests, builds the MSVC executable, runs the UI smoke test, and publishes a ZIP and its SHA-256 checksum as a GitHub Release. A failed check publishes nothing.

## Release steps

1. **Bump the version** in `Cargo.toml`, then update `Cargo.lock`:

   ```powershell
   cargo update -p sentinel-ssh --offline
   ```

   Use a suffix such as `0.2.0-rc.1` for a pre-release. It is labelled Pre-release and is not marked Latest.

2. **Commit and push** the release commit. Make sure your working tree is clean.

3. **Do a test run** (recommended): open **Actions → Release → Run workflow** on your branch. This builds and checks everything and uploads the ZIP as an Actions artifact, but does not publish anything.

4. **Tag and push.** The tag must be `v` plus the exact Cargo version, or the workflow stops.

   ```powershell
   git tag -a v0.1.0 -m "SentinelSSH v0.1.0"
   git push origin v0.1.0
   ```

5. **Watch** **Actions → Release** until both jobs pass.

6. **Check the release** on the [Releases page](https://github.com/munna2053/ssh-client-plus/releases). It should have these assets:
   - `sentinel-ssh-<version>-windows-x64.zip`
   - `sentinel-ssh-<version>-windows-x64.zip.sha256`

## If something fails

- **Build failed:** fix it in a new commit and release under a new version. Don't move a tag after it has been published.
- **Only the publish job failed** and no release was created: re-run the failed jobs.
- **Release already exists:** the workflow never overwrites it. Delete it on GitHub first if you really need to re-publish.

## Build a ZIP locally

```powershell
# MSVC build (needs the Visual Studio C++ tools)
cargo build --release --locked --target x86_64-pc-windows-msvc
.\scripts\package-release.ps1 -Version 0.1.0

# Portable GNU/LLVM build from scripts\dev.ps1
.\scripts\package-release.ps1 -Version 0.1.0 -Executable .\target\slint\release\sentinel-ssh.exe
```

The output goes to `target\release-assets`. The ZIP contains only the executable, README, license, and threat model.

## Update the application icon

1. Edit `assets/icon/sentinel-ssh.svg` (32 px and larger) or `sentinel-ssh-small.svg` (16–24 px).
2. Regenerate the `.ico` with GIMP 3. Add `-PreviewDirectory <folder>` to save a PNG of each size for review.

   ```powershell
   .\scripts\build-icon.ps1
   ```

3. Commit the updated `.ico`. `build.rs` embeds it in the executable.

## Notes

- If PowerShell blocks the scripts, run them as `powershell -ExecutionPolicy Bypass -File <script> ...`.
- Users download the ZIP from **Assets**. GitHub's **Source code** archives do not contain the executable.
- Releases from a private repository can only be downloaded by people with access to it.
- To check a download, compare `Get-FileHash <zip> -Algorithm SHA256` with the first value in the `.sha256` file.
- The executable is unsigned, and there is no installer or auto-updater yet. The open security gates are listed in the [threat model](THREAT_MODEL.md).
