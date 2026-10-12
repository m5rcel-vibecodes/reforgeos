$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$binary = Join-Path $repoRoot 'target\release\reforge.exe'
if (-not (Test-Path -LiteralPath $binary)) { throw 'Run cargo build --release --locked first' }
$dist = Join-Path $repoRoot 'dist'
New-Item -ItemType Directory -Force -Path $dist | Out-Null
$archive = Join-Path $dist 'reforge-windows-x86_64.zip'
$files = @($binary, (Join-Path $repoRoot 'README.md'), (Join-Path $repoRoot 'LICENSE-MIT'), (Join-Path $repoRoot 'LICENSE-APACHE'), (Join-Path $repoRoot 'THIRD-PARTY-NOTICES.md'), (Join-Path $repoRoot 'third-party-licenses'), (Join-Path $repoRoot 'docs'), (Join-Path $repoRoot 'examples'))
# Cargo sources can have pre-1980 timestamps, which Compress-Archive rejects.
# Write fixed entry timestamps without changing source file metadata.
Add-Type -AssemblyName System.IO.Compression
$temporaryArchive = Join-Path $dist ([Guid]::NewGuid().ToString() + '.zip.tmp')
$stream = [IO.File]::Open($temporaryArchive, [IO.FileMode]::CreateNew)
try {
    $zip = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create, $true)
    try {
        foreach ($item in $files) {
            $paths = if (Test-Path -LiteralPath $item -PathType Container) { Get-ChildItem -LiteralPath $item -Recurse -File | Sort-Object FullName } else { Get-Item -LiteralPath $item }
            foreach ($file in $paths) {
                $entryName = if ($file.FullName -eq $binary) { 'reforge.exe' } else { $file.FullName.Substring($repoRoot.Length + 1).Replace('\', '/') }
                $entry = $zip.CreateEntry($entryName, [IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = [DateTimeOffset]::new(2000, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
                $entryStream = $entry.Open()
                $sourceStream = [IO.File]::OpenRead($file.FullName)
                try { $sourceStream.CopyTo($entryStream) } finally { $sourceStream.Dispose(); $entryStream.Dispose() }
            }
        }
    } finally { $zip.Dispose() }
} finally { $stream.Dispose() }
Move-Item -LiteralPath $temporaryArchive -Destination $archive -Force
$hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath "$archive.sha256" -Value "$hash  reforge-windows-x86_64.zip" -Encoding ascii
Write-Output $archive
