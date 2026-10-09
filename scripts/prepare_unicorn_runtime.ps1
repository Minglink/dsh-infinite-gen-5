# Maintainer-only pruning of a pinned wheel's unused static linking archive.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$vendor = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\worker\vendor'))
$archive = [IO.Path]::GetFullPath((Join-Path $vendor 'unicorn\lib\unicorn.lib'))
if (-not $archive.StartsWith($vendor + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid vendor target' }
$provenance = Join-Path $vendor 'runtime-subset.json'
if (-not (Test-Path -LiteralPath $archive)) {
    if (-not (Test-Path -LiteralPath $provenance)) { throw 'Archive absent without runtime-subset provenance' }
    Write-Output 'Unicorn runtime subset already prepared.'
    exit 0
}
$hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($hash -ne '60a95ffb6572942b7db1f57901d23e664ed22a54a7d92dfcad15fc3e3ef1f724') { throw 'Unexpected Unicorn static archive; refusing to prune' }
$metadata = Join-Path $vendor 'unicorn-2.1.4.dist-info'
$record = Join-Path $metadata 'RECORD'
$original = Join-Path $vendor 'provenance\unicorn-2.1.4-original-RECORD.csv'
New-Item -ItemType Directory -Path (Split-Path -Parent $original) -Force | Out-Null
if (-not (Test-Path -LiteralPath $original)) { Copy-Item -LiteralPath $record -Destination $original }
$lines = @(Get-Content -LiteralPath $record -Encoding UTF8)
$removed = @($lines | Where-Object { $_.StartsWith('unicorn/lib/unicorn.lib,', [StringComparison]::Ordinal) })
if ($removed.Count -ne 1) { throw 'Pinned RECORD must contain one static archive entry' }
$bytes = (Get-Item -LiteralPath $archive).Length
# This file is not loaded by the Python bindings; unicorn.dll and all bindings/licenses remain.
Remove-Item -LiteralPath $archive
$retained = @($lines | Where-Object { -not $_.StartsWith('unicorn/lib/unicorn.lib,', [StringComparison]::Ordinal) })
[IO.File]::WriteAllText($record, (($retained -join "`n") + "`n"), [Text.UTF8Encoding]::new($false))
$info = [ordered]@{
    schemaVersion = 1; wheel = 'unicorn-2.1.4-cp37-abi3-win_amd64.whl'
    wheelSha256 = 'd7107500c64ce5c168fbff6bef9485b5db1350050036f4cea568650cf8bdbdf5'
    source = 'https://pypi.org/project/unicorn/2.1.4/'
    removed = @(@{ path = 'unicorn/lib/unicorn.lib'; bytes = $bytes; sha256 = $hash; reason = 'Unused static linking archive; Python runtime loads unicorn.dll' })
    originalRecord = 'provenance/unicorn-2.1.4-original-RECORD.csv'
    binariesModified = $false
}
[IO.File]::WriteAllText($provenance, (($info | ConvertTo-Json -Depth 6) + "`n"), [Text.UTF8Encoding]::new($false))
Write-Output "Pruned unused static archive: $bytes bytes. Run test_cpu_emulator.py before distributing."
