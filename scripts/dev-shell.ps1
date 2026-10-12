# Dot-source this file to expose locally installed development tools in this shell.
$repoRoot = Split-Path -Parent $PSScriptRoot
$rustBin = Join-Path $env:USERPROFILE '.cargo\bin'
$cmakeBin = Join-Path $env:ProgramFiles 'CMake\bin'
foreach ($directory in @($rustBin, $cmakeBin)) {
    if (Test-Path -LiteralPath $directory) { $env:PATH = "$directory;$env:PATH" }
}
$jdkRoot = Join-Path $env:ProgramFiles 'Eclipse Adoptium'
if (Test-Path -LiteralPath $jdkRoot) {
    $jdk = Get-ChildItem -LiteralPath $jdkRoot -Directory | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'bin\java.exe') } | Sort-Object Name -Descending | Select-Object -First 1
    if ($jdk) { $env:JAVA_HOME = $jdk.FullName }
}
$toolRoot = Join-Path $repoRoot '.tools'
if (Test-Path -LiteralPath $toolRoot) {
    $ghidra = Get-ChildItem -LiteralPath $toolRoot -Directory | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'Ghidra\application.properties') } | Sort-Object Name -Descending | Select-Object -First 1
    if ($ghidra) { $env:GHIDRA_INSTALL_DIR = $ghidra.FullName }
}
Write-Output 'Development tools configured for this PowerShell session. Run cargo build --release or target\release\reforge.exe doctor.'
