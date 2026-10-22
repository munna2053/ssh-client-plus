SentinelSSH for Windows (x64)

1. Extract the entire ZIP to a folder on your PC.
2. Enable OpenSSH Client in Windows Settings > Optional features if needed.
3. Run sentinel-ssh.exe and create or unlock your vault.

Requires Windows 11 x64. Rust, Visual Studio, and an installer are not needed.
This executable is currently unsigned.

Your saved servers, passwords, settings, and generated keys live under
%LOCALAPPDATA%\SentinelSSH, separately from this application folder.
To update, close SentinelSSH and replace the extracted application files.
Keep your existing application-data directory intact.

The vault is bound to the Windows account/device that created it. Copying its
database to another PC is not a supported backup or migration workflow.

This is a preview release. See THREAT_MODEL.md for security boundaries and
remaining release gates. Application code uses the MIT license in LICENSE;
Slint attribution is available through the application's About screen.

Project and documentation:
https://github.com/munna2053/ssh-client-plus

Downloads and release notes:
https://github.com/munna2053/ssh-client-plus/releases
