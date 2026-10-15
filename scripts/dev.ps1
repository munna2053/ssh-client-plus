param(
    [ValidateSet('check', 'test', 'build', 'run', 'fmt', 'clippy')]
    [string]$Action = 'run',
    [switch]$Release,
    [switch]$Portable,
    [switch]$Offline,
    [switch]$Preview
)

$ErrorActionPreference = 'Stop'
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$savedLocation = Get-Location
$savedEnvironment = @{}
foreach ($environmentName in @('RUSTUP_HOME', 'CARGO_HOME', 'CARGO_TARGET_DIR', 'CARGO_ENCODED_RUSTFLAGS', 'SENTINEL_PORTABLE_LLD')) {
    $savedEnvironment[$environmentName] = [Environment]::GetEnvironmentVariable($environmentName, 'Process')
}

try {
    Set-Location -LiteralPath $projectRoot
    if ([string]::IsNullOrEmpty($env:CARGO_TARGET_DIR)) { $env:CARGO_TARGET_DIR = Join-Path $projectRoot 'target\slint' }
    $localCargo = Join-Path $projectRoot '.tools\cargo\bin\cargo.exe'
    $cargoExecutable = 'cargo'
    if (Test-Path -LiteralPath $localCargo) {
        $env:RUSTUP_HOME = Join-Path $projectRoot '.tools\rustup'
        $env:CARGO_HOME = Join-Path $projectRoot '.tools\cargo'
        $cargoExecutable = $localCargo
    }

    $cargoArguments = @()
    if ($Portable) {
        $gnuToolchain = '1.90.0-x86_64-pc-windows-gnu'
        if ([string]::IsNullOrEmpty($env:RUSTUP_HOME)) {
            throw 'Portable mode requires the project-local Rust toolchain in .tools. See README.md.'
        }
        $gnuRoot = Join-Path $env:RUSTUP_HOME "toolchains\$gnuToolchain\lib\rustlib\x86_64-pc-windows-gnu"
        $archiveTool = Join-Path $gnuRoot 'bin\llvm-ar.exe'
        $linkerTool = Join-Path $gnuRoot 'bin\gcc-ld\ld.lld.exe'
        if (!(Test-Path -LiteralPath $archiveTool) -or !(Test-Path -LiteralPath $linkerTool)) {
            throw 'Install the GNU toolchain and its llvm-tools component first. See README.md.'
        }
        # LLVM dispatches its archive tool to dlltool based on the executable name.
        $dllTool = Join-Path $projectRoot '.tools\llvm-dlltool.exe'
        if (!(Test-Path -LiteralPath $dllTool)) {
            Copy-Item -LiteralPath $archiveTool -Destination $dllTool
        }
        $wrapperDirectory = Join-Path $projectRoot '.tools\portable-linker'
        [System.IO.Directory]::CreateDirectory($wrapperDirectory) | Out-Null
        $linkerWrapper = Join-Path $wrapperDirectory 'ld.lld.exe'
        $wrapperSource = Join-Path $projectRoot 'scripts\portable-linker.rs'
        if (!(Test-Path -LiteralPath $linkerWrapper) -or (Get-Item -LiteralPath $wrapperSource).LastWriteTimeUtc -gt (Get-Item -LiteralPath $linkerWrapper).LastWriteTimeUtc) {
            $rustCompiler = Join-Path $env:RUSTUP_HOME "toolchains\$gnuToolchain\bin\rustc.exe"
            & $rustCompiler --edition 2024 $wrapperSource -o $linkerWrapper -C "linker=$linkerTool" -C linker-flavor=ld -C "dlltool=$dllTool"
            if ($LASTEXITCODE -ne 0) { throw 'Cannot build the portable linker wrapper.' }
        }
        $env:SENTINEL_PORTABLE_LLD = Join-Path $gnuRoot 'bin\rust-lld.exe'
        $env:CARGO_ENCODED_RUSTFLAGS = @('-C', "linker=$linkerWrapper", '-C', 'linker-flavor=ld', '-C', 'link-self-contained=yes', '-C', "dlltool=$dllTool") -join [char]0x1F
        if ($Action -eq 'fmt') {
            $env:CARGO_ENCODED_RUSTFLAGS = $null
            $cargoArguments += '+1.90.0-x86_64-pc-windows-msvc'
        } else {
            $cargoArguments += "+$gnuToolchain"
        }
    }

    $cargoArguments += $Action
    if ($Action -eq 'fmt') {
        $cargoArguments += @('--all', '--', '--check')
    } else {
        $cargoArguments += '--locked'
        if ($Offline) { $cargoArguments += '--offline' }
        if ($Release -and $Action -in @('build', 'run', 'check', 'test')) { $cargoArguments += '--release' }
        if ($Action -eq 'test') { $cargoArguments += @('--', '--test-threads=1') }
        if ($Action -eq 'clippy') { $cargoArguments += @('--all-targets', '--', '-D', 'warnings') }
    }
    if ($Preview -and $Action -eq 'run') { $cargoArguments += @('--', '--ui-preview') }
    & $cargoExecutable @cargoArguments
    if ($LASTEXITCODE -ne 0) { throw "Cargo $Action failed with exit code $LASTEXITCODE." }
} finally {
    Set-Location -LiteralPath $savedLocation
    foreach ($environmentName in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($environmentName, $savedEnvironment[$environmentName], 'Process')
    }
}
