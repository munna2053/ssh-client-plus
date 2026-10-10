param(
    [ValidateSet('check', 'test', 'build', 'run', 'fmt', 'clippy')]
    [string]$Action = 'run',
    [switch]$Release,
    [switch]$Portable,
    [switch]$Offline
)

$ErrorActionPreference = 'Stop'
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$savedLocation = Get-Location
$savedEnvironment = @{}
foreach ($environmentName in @('RUSTUP_HOME', 'CARGO_HOME', 'CARGO_ENCODED_RUSTFLAGS')) {
    $savedEnvironment[$environmentName] = [Environment]::GetEnvironmentVariable($environmentName, 'Process')
}

try {
    Set-Location -LiteralPath $projectRoot
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
        $env:CARGO_ENCODED_RUSTFLAGS = @('-C', "linker=$linkerTool", '-C', 'linker-flavor=ld', '-C', "dlltool=$dllTool") -join [char]0x1F
        if ($Action -in @('fmt', 'clippy')) {
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
    & $cargoExecutable @cargoArguments
    if ($LASTEXITCODE -ne 0) { throw "Cargo $Action failed with exit code $LASTEXITCODE." }
} finally {
    Set-Location -LiteralPath $savedLocation
    foreach ($environmentName in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($environmentName, $savedEnvironment[$environmentName], 'Process')
    }
}
