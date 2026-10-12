# Generate Windows runtime dependency notices from the resolved Cargo graph.
param([string]$Cargo = 'cargo')
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$rows = & $Cargo +stable tree --locked --offline --workspace --target x86_64-pc-windows-msvc --edges normal --prefix none --format '{p}|{l}'
if ($LASTEXITCODE -ne 0) { throw 'cargo tree failed' }
$registry = Join-Path $env:USERPROFILE '.cargo\registry\src'
$licenseRoot = Join-Path $repoRoot 'third-party-licenses'
New-Item -ItemType Directory -Force -Path $licenseRoot | Out-Null
$notice = [System.Collections.Generic.List[string]]::new()
$notice.Add('# Third-party notices')
$notice.Add('')
$notice.Add('Resolved Windows runtime Rust dependencies. License texts are retained in third-party-licenses/. SQLite is in the public domain; its Rust wrapper is MIT. Optional Ghidra, Java and CMake are separately installed and not bundled.')
$notice.Add('')
$notice.Add('| Package | Declared license |')
$notice.Add('| --- | --- |')
$packages = @{}
foreach ($row in $rows) {
    if ($row -match '^([a-zA-Z0-9_-]+) v([^ ]+)\|(.+)$') {
        $name = $Matches[1]
        $version = $Matches[2]
        $license = $Matches[3] -replace ' \(\*\)$', ''
        $packages["$name-$version"] = $license
    }
}
foreach ($key in ($packages.Keys | Sort-Object)) {
    $source = Get-ChildItem -LiteralPath $registry -Directory | ForEach-Object { Join-Path $_.FullName $key } | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $source) { throw "Dependency source missing: $key" }
    $dest = Join-Path $licenseRoot $key
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    $texts = Get-ChildItem -LiteralPath $source -File | Where-Object { $_.Name -match '^(LICENSE|LICENCE|COPYING|NOTICE|COPYRIGHT)' }
    if (-not $texts -and -not (Get-ChildItem -LiteralPath $dest -File)) { throw "No license text found: $key; obtain its upstream license and place it in $dest" }
    foreach ($text in $texts) { Copy-Item -LiteralPath $text.FullName -Destination $dest }
    $notice.Add("| $key | $($packages[$key]) |")
}
$notice | Set-Content -LiteralPath (Join-Path $repoRoot 'THIRD-PARTY-NOTICES.md') -Encoding utf8
$apache = Get-ChildItem -LiteralPath $registry -Directory | ForEach-Object { Join-Path $_.FullName 'adler2-2.0.1\LICENSE-APACHE' } | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
Copy-Item -LiteralPath $apache -Destination (Join-Path $repoRoot 'LICENSE-APACHE')
