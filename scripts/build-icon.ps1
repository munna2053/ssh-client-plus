param(
    [string]$Gimp,
    [string]$PreviewDirectory
)

# Regenerates assets\icon\sentinel-ssh.ico from its SVG sources with GIMP 3's batch mode.
$ErrorActionPreference = 'Stop'
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ([string]::IsNullOrEmpty($Gimp)) {
    $Gimp = Get-ChildItem -Path @("$env:LOCALAPPDATA\Programs\GIMP 3\bin", "$env:ProgramFiles\GIMP 3\bin") -Filter 'gimp-console-3.exe' -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
    if ([string]::IsNullOrEmpty($Gimp)) { throw 'Cannot find gimp-console-3.exe. Install GIMP 3 or pass -Gimp.' }
}
$env:SENTINEL_ICON_DIR = Join-Path $projectRoot 'assets\icon'
$env:SENTINEL_PREVIEW_DIR = $PreviewDirectory
if (![string]::IsNullOrEmpty($PreviewDirectory)) {
    [System.IO.Directory]::CreateDirectory($PreviewDirectory) | Out-Null
}
$script = (Join-Path $PSScriptRoot 'gimp-export-icon.py').Replace('\', '/')
try {
    & $Gimp -i --no-data --no-fonts --quit --batch-interpreter=python-fu-eval -b "exec(open(r'$script', encoding='utf-8').read())"
    if ($LASTEXITCODE -ne 0) { throw "GIMP failed with exit code $LASTEXITCODE." }
} finally {
    Remove-Item Env:SENTINEL_ICON_DIR, Env:SENTINEL_PREVIEW_DIR -ErrorAction SilentlyContinue
}
