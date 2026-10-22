[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$')]
    [string]$Version,
    [string]$Executable,
    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ([string]::IsNullOrEmpty($Executable)) {
    $Executable = Join-Path $projectRoot 'target\x86_64-pc-windows-msvc\release\sentinel-ssh.exe'
}
if ([string]::IsNullOrEmpty($OutputDirectory)) {
    $OutputDirectory = Join-Path $projectRoot 'target\release-assets'
}
$sourceExecutable = (Resolve-Path -LiteralPath $Executable).ProviderPath
if (!(Test-Path -LiteralPath $sourceExecutable -PathType Leaf)) {
    throw 'Build the release executable before packaging.'
}

[System.IO.Directory]::CreateDirectory($OutputDirectory) | Out-Null
$resolvedOutput = (Resolve-Path -LiteralPath $OutputDirectory).ProviderPath
$stagingRoot = Join-Path $resolvedOutput ('.staging-' + [Guid]::NewGuid().ToString('N'))
$packageName = "sentinel-ssh-$Version-windows-x64"
$packageDirectory = Join-Path $stagingRoot $packageName
$zipPath = Join-Path $resolvedOutput "$packageName.zip"
$utf8 = [System.Text.UTF8Encoding]::new($false)

try {
    New-Item -ItemType Directory -Path $packageDirectory | Out-Null
    # Package only explicitly selected distribution files, never a workspace glob.
    Copy-Item -LiteralPath $sourceExecutable -Destination (Join-Path $packageDirectory 'sentinel-ssh.exe')
    Copy-Item -LiteralPath (Join-Path $projectRoot 'LICENSE') -Destination $packageDirectory
    Copy-Item -LiteralPath (Join-Path $projectRoot 'docs\WINDOWS-README.txt') -Destination (Join-Path $packageDirectory 'README.txt')
    Copy-Item -LiteralPath (Join-Path $projectRoot 'docs\THREAT_MODEL.md') -Destination $packageDirectory
    Compress-Archive -LiteralPath $packageDirectory -DestinationPath $zipPath -CompressionLevel Optimal -Force

    $digest = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    # Use LF and no BOM so both sha256sum and PowerShell can check this file.
    [System.IO.File]::WriteAllText("$zipPath.sha256", "$digest  $packageName.zip`n", $utf8)
    $notes = @"
Windows x64 portable build of SentinelSSH $Version.

Download ``$packageName.zip`` under **Assets**, extract the ZIP, and run ``sentinel-ssh.exe``. Rust and build tools are not needed.

Requires Windows 11 x64 and the Windows **OpenSSH Client** optional feature. The executable is currently unsigned. This preview stores its vault under ``%LOCALAPPDATA%\SentinelSSH``; the ZIP contains no saved servers, credentials, or private keys.

The accompanying ``.sha256`` file contains the ZIP's SHA-256 checksum. See the bundled README and threat model for setup and current limitations.

"@
    [System.IO.File]::WriteAllText((Join-Path $resolvedOutput 'RELEASE_NOTES.md'), $notes.Replace("`r`n", "`n"), $utf8)
    Write-Output "Created $zipPath"
    Write-Output "Created $zipPath.sha256"
} finally {
    if (Test-Path -LiteralPath $stagingRoot) {
        # Delete only this invocation's staging folder, directly within the resolved output directory.
        $resolvedStaging = (Resolve-Path -LiteralPath $stagingRoot).ProviderPath
        if ((Split-Path -Parent $resolvedStaging) -ne $resolvedOutput) {
            throw 'Refusing to remove a staging directory outside the release output directory.'
        }
        Remove-Item -LiteralPath $resolvedStaging -Recurse -Force
    }
}
