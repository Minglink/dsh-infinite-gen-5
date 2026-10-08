[CmdletBinding()]
param(
    [string]$RuntimeRoot,
    [string]$OutputRoot = (Join-Path $env:USERPROFILE '.dsh\ig5\artifacts'),
    [switch]$IncludeProjects
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'runtime_pack.ps1')
if ($IncludeProjects) { throw '自包含发行包不分发用户项目；请单独备份项目。' }
$source = Get-IG5FullPath (Join-Path $PSScriptRoot '..')
if (-not $RuntimeRoot) { $RuntimeRoot = Join-Path $source 'runtimes' }
$runtimeInput = Get-IG5FullPath $RuntimeRoot
$output = Get-IG5FullPath $OutputRoot
$package = Get-Content -LiteralPath (Join-Path $source 'package.json') -Raw -Encoding UTF8 | ConvertFrom-Json
# Validate inputs before creating output or staging directories.
Assert-IG5PluginSource $source
$validated = Assert-IG5RuntimePack $runtimeInput
if ($validated.Manifest.pluginVersion -and [string]$validated.Manifest.pluginVersion -ne [string]$package.version) { throw '运行包与插件版本不符' }
foreach ($inputPath in @($source, $runtimeInput)) {
    if ($output -eq $inputPath -or $output.StartsWith($inputPath + '\', [StringComparison]::OrdinalIgnoreCase)) { throw '便携包不能写入输入目录内部' }
}
if ((Test-Path -LiteralPath $output) -and ((Get-Item -LiteralPath $output).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw '发行输出目录不能为链接' }
$token = [Guid]::NewGuid().ToString('N')
$destination = Join-Path $output ("IG5-portable-" + $package.version + '-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + $token.Substring(0, 8))
$stage = Join-Path $output ".ig5-package-$token"
try {
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    Copy-IG5Pack $source (Join-Path $stage 'plugin') @('runtimes')
    Copy-IG5Pack $runtimeInput (Join-Path $stage 'plugin\runtimes')
    Write-IG5RuntimeManifest $validated (Join-Path $stage 'plugin\runtimes') ([string]$package.version)
    $null = Assert-IG5RuntimePack (Join-Path $stage 'plugin\runtimes')
    $instructions = @'
IG5 SELF-CONTAINED PORTABLE PACKAGE

Requires Windows x64 and an installed DeepSeek Harness profile.
The plugin contains complete Ghidra/Java/Python and x64dbg/Python runtimes.
Keep plugin/runtimes intact; no downloads, setup scripts or system PATH changes are required.

Install from PowerShell:
  & .\plugin\install.ps1
Then restart DeepSeek Harness and call ig5_doctor.

Reverse is optional and separately configured on the destination computer.
DeepSeek Harness and the commercial runtime are not bundled.
Upstream licenses, notices, source audit assets and SHA-256 manifests are preserved.
User projects, sessions, downloads and build caches are excluded.
'@
    [IO.File]::WriteAllText((Join-Path $stage 'INSTALL.txt'), $instructions, [Text.UTF8Encoding]::new($false))
    $records = @(Get-IG5PackFiles $stage | Sort-Object FullName | ForEach-Object {
        @{ path = Get-IG5RelativePath $stage $_.FullName; bytes = $_.Length;
           sha256 = Get-IG5Hash $_.FullName }
    })
    $manifest = @{ schemaVersion = 1; pluginVersion = $package.version; version = $package.version; platform = 'win32-x64'; createdAt = [DateTime]::UtcNow.ToString('o');
        engines = @('ghidra', 'x64dbg'); includesProjects = $false; files = $records }
    [IO.File]::WriteAllText((Join-Path $stage 'manifest.json'), ($manifest | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $stage -Destination $destination
} catch {
    $safe = [IO.Path]::GetFullPath($stage)
    if (-not $safe.StartsWith($output + '\', [StringComparison]::OrdinalIgnoreCase)) { throw '拒绝清理输出目录之外的暂存路径' }
    if (Test-Path -LiteralPath $safe) {
        if ((Get-Item -LiteralPath $safe).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw '拒绝清理链接暂存目录' }
        Remove-IG5Tree $safe
    }
    throw
}
Write-Output ("PORTABLE_ROOT=" + $destination)
Write-Output ("FILES=" + $records.Count)
$totalBytes = [long]0
foreach ($record in $records) { $totalBytes += [long]$record.bytes }
Write-Output ("BYTES=" + $totalBytes)
