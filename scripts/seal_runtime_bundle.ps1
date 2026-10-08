# Maintainer command: seal actual, local runtimes into a complete distribution.
[CmdletBinding()]
param([string]$RuntimeRoot = (Join-Path $PSScriptRoot '..\runtimes'))
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'runtime_pack.ps1')
$base = Get-IG5FullPath $RuntimeRoot
$source = Get-IG5FullPath (Join-Path $PSScriptRoot '..')
if ($base -ne (Join-Path $source 'runtimes')) { throw '只允许封存当前源码内的 runtimes；外部运行包请先复制入源码目录。' }
if (-not (Test-Path -LiteralPath $base -PathType Container)) { throw "缺少运行目录: $base" }
$version = (Get-Content -LiteralPath (Join-Path $source 'package.json') -Raw -Encoding UTF8 | ConvertFrom-Json).version
$records = @(Get-IG5PackFiles $base | Sort-Object FullName | Where-Object { $_.FullName -ne (Join-Path $base 'manifest.json') } | ForEach-Object {
    @{ path = Get-IG5RelativePath $base $_.FullName; bytes = $_.Length;
       sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
})
$manifest = @{schemaVersion=1; pluginVersion=$version; platform='win32-x64'; engines=@('ghidra','x64dbg'); createdAt=[DateTime]::UtcNow.ToString('o'); files=$records}
$manifestPath = Join-Path $base 'manifest.json'
$prior = if (Test-Path -LiteralPath $manifestPath) { [IO.File]::ReadAllBytes($manifestPath) } else { $null }
try {
    [IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    $validated = Assert-IG5RuntimePack $base
    Write-Output "SEALED_FILES=$($validated.Files)"
    Write-Output "SEALED_BYTES=$(($records | Measure-Object -Property bytes -Sum).Sum)"
} catch {
    if ($null -ne $prior) { [IO.File]::WriteAllBytes($manifestPath, $prior) }
    else { Remove-Item -LiteralPath $manifestPath -Force -ErrorAction SilentlyContinue }
    throw
}
