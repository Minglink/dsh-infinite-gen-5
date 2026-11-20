[CmdletBinding()]
param(
    [string]$RuntimeRoot,
    [string]$OutputRoot = (Join-Path $env:USERPROFILE '.dsh\ig5\releases'),
    [string]$CompanionSourcesManifest,
    [switch]$IncludeFullSources,
    [switch]$IncludeDevTests,
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
$pluginVersion = [string]$package.version
$isV14Plus = Test-IG5VersionAtLeast $pluginVersion '1.4.0'
# Validate inputs before creating output or staging directories.
Assert-IG5PluginSource $source -CoreOnly:$($isV14Plus -and -not $IncludeFullSources)
$validated = Assert-IG5RuntimePack $runtimeInput
if ($validated.Manifest.pluginVersion -and -not (Test-IG5RuntimeVersion ([string]$validated.Manifest.pluginVersion) $pluginVersion)) { throw '运行包与插件版本不符' }
if ($isV14Plus -and -not $IncludeFullSources -and -not $CompanionSourcesManifest) {
    $autoCompanion = Join-Path (Split-Path $runtimeInput -Parent) 'companion-sources.json'
    if (Test-IG5Path $autoCompanion Leaf) { $CompanionSourcesManifest = $autoCompanion }
}
$companionObj = $null
$sourceExcludeDirs = @('runtimes')
$srcManifest = $null
if ($isV14Plus -and -not $IncludeFullSources -and $CompanionSourcesManifest) {
    $companionFull = Get-IG5FullPath $CompanionSourcesManifest
    if (-not (Test-IG5Path $companionFull Leaf)) { throw "找不到伴随源码清单: $companionFull" }
    $companionObj = Read-IG5Text $companionFull | ConvertFrom-Json
    $srcManifest = Read-IG5Text (Join-Path $source 'third_party\sources\manifest.json') | ConvertFrom-Json
    $sourceExcludeDirs += 'third_party/sources'
}
foreach ($inputPath in @($source, $runtimeInput)) {
    if ($output -eq $inputPath -or $output.StartsWith($inputPath + '\', [StringComparison]::OrdinalIgnoreCase)) { throw '便携包不能写入输入目录内部' }
}
if ((Test-Path -LiteralPath $output) -and ((Get-Item -LiteralPath $output).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw '发行输出目录不能为链接' }
$token = [Guid]::NewGuid().ToString('N')
$destination = Join-Path $output ("IG5-portable-" + $pluginVersion + '-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + $token.Substring(0, 8))
$stage = Join-Path $output ".ig5-package-$token"
try {
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    $script:IG5SkippedRootFiles.Clear()
    $usePortableFilter = $isV14Plus -and -not $IncludeDevTests
    $sampleSpecific = if ($usePortableFilter) { @(Get-IG5SampleSpecificFiles $source) } else { @() }
    Copy-IG5Pack $source (Join-Path $stage 'plugin') $sourceExcludeDirs -PortableRelease:$usePortableFilter -SampleSpecificFiles $sampleSpecific
    if ($companionObj) {
        $stageSources = Join-Path $stage 'plugin\third_party\sources'
        [IO.Directory]::CreateDirectory((ConvertTo-IG5IOPath $stageSources)) | Out-Null
        [IO.File]::Copy((ConvertTo-IG5IOPath (Join-Path $source 'third_party\sources\manifest.json')), (ConvertTo-IG5IOPath (Join-Path $stageSources 'manifest.json')), $true)
        [IO.File]::Copy((ConvertTo-IG5IOPath (Get-IG5FullPath $CompanionSourcesManifest)), (ConvertTo-IG5IOPath (Join-Path $stageSources 'companion-sources.json')), $true)
        foreach ($srcEntry in $srcManifest.sources) {
            $invRel = ([string]$srcEntry.fileInventory).Replace('\', '/')
            $srcInv = Resolve-IG5PackPath (Join-Path $source 'third_party\sources') $invRel
            $dstInv = Resolve-IG5PackPath $stageSources $invRel
            [IO.Directory]::CreateDirectory((ConvertTo-IG5IOPath (Split-Path $dstInv -Parent))) | Out-Null
            [IO.File]::Copy((ConvertTo-IG5IOPath $srcInv), (ConvertTo-IG5IOPath $dstInv), $true)
        }
    }
    Copy-IG5Pack $runtimeInput (Join-Path $stage 'plugin\runtimes')
    Write-IG5RuntimeManifest $validated (Join-Path $stage 'plugin\runtimes') $pluginVersion
    $null = Assert-IG5RuntimePack (Join-Path $stage 'plugin\runtimes')
    Assert-IG5PluginSource (Join-Path $stage 'plugin')
    $companionNote = if ($companionObj) {
        "`r`nThird-party upstream source trees are provided as companion archive $($companionObj.archiveName) (SHA-256: $($companionObj.archiveSha256)); notices, licenses, manifest.json and provenance inventories remain bundled inside plugin/third_party/sources."
    } else { '' }
    $instructions = @'
IG5 SELF-CONTAINED PORTABLE PACKAGE

Requires Windows x64 and an installed DeepSeek Harness (>= 0.2.0-rc.1, tested on 0.2.2-rc.x).
The plugin contains complete Ghidra/Java/Python and x64dbg/Python runtimes.
Keep plugin/runtimes intact; no downloads, setup scripts or system PATH changes are required.

One-click Install (Recommended):
  Double-click install.bat

Or install from PowerShell:
  & .\plugin\install.ps1
Then restart DeepSeek Harness and call ig5_doctor.

Reverse is the default bundled analysis lane (reverseProvider=bundled, provider=ghidra).
44 public tools include independent HTTP/HTTPS capture and multi-process observation; no Burp program is required.
The optional commercial compatibility provider requires a separately licensed local installation.
DeepSeek Harness and commercial programs/licenses are not bundled.
Upstream licenses, notices, source audit assets and SHA-256 manifests are preserved.
User projects, sessions, downloads and build caches are excluded.
'@ + $companionNote
    [IO.File]::WriteAllText((Join-Path $stage 'INSTALL.txt'), $instructions, [Text.UTF8Encoding]::new($false))
    $installBat = @(
        '@echo off',
        'setlocal',
        'echo.',
        'echo ========================================================',
        'echo   Infinite Gen 5 (IG5) - DeepSeek Harness Plugin Setup',
        'echo ========================================================',
        'echo.',
        'if not exist "%USERPROFILE%\.dsh\profiles" (',
        '  echo [!] "%USERPROFILE%\.dsh\profiles" not found.',
        '  echo     Please install and launch DeepSeek Harness once, then close it and re-run install.bat.',
        '  if not defined IG5_NO_PAUSE pause',
        '  exit /b 1',
        ')',
        'tasklist /FI "IMAGENAME eq DeepSeek Harness.exe" 2>nul | find /I "DeepSeek Harness.exe" >nul',
        'if "%ERRORLEVEL%"=="0" (',
        '  echo [*] Stopping running DeepSeek Harness.exe...',
        '  taskkill /IM "DeepSeek Harness.exe" /F >nul 2>&1',
        '  timeout /t 2 /nobreak >nul',
        ')',
        'powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0plugin\install.ps1"',
        'if errorlevel 1 (',
        '  echo.',
        '  echo [X] Installation failed. Please review the error above.',
        '  if not defined IG5_NO_PAUSE pause',
        '  exit /b 1',
        ')',
        'echo.',
        'if exist "%LOCALAPPDATA%\Programs\DeepSeek Harness\DeepSeek Harness.exe" (',
        '  echo [*] Launching DeepSeek Harness...',
        '  start "" "%LOCALAPPDATA%\Programs\DeepSeek Harness\DeepSeek Harness.exe"',
        ')',
        'echo [OK] Setup complete! Call ig5_doctor inside DeepSeek Harness to verify.',
        'if not defined IG5_NO_PAUSE pause'
    ) -join "`r`n"
    [IO.File]::WriteAllText((Join-Path $stage 'install.bat'), ($installBat + "`r`n"), [Text.UTF8Encoding]::new($false))
    $uninstallBat = @(
        '@echo off',
        'setlocal',
        'tasklist /FI "IMAGENAME eq DeepSeek Harness.exe" 2>nul | find /I "DeepSeek Harness.exe" >nul',
        'if "%ERRORLEVEL%"=="0" (',
        '  taskkill /IM "DeepSeek Harness.exe" /F >nul 2>&1',
        '  timeout /t 2 /nobreak >nul',
        ')',
        'powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0plugin\uninstall.ps1"',
        'if not defined IG5_NO_PAUSE pause'
    ) -join "`r`n"
    [IO.File]::WriteAllText((Join-Path $stage 'uninstall.bat'), ($uninstallBat + "`r`n"), [Text.UTF8Encoding]::new($false))
    $records = @(Get-IG5PackFiles $stage | Sort-Object FullName | ForEach-Object {
        @{ path = Get-IG5RelativePath $stage $_.FullName; bytes = $_.Length;
           sha256 = Get-IG5Hash $_.FullName }
    })
    $manifest = @{ schemaVersion = 1; pluginVersion = $pluginVersion; version = $pluginVersion; platform = 'win32-x64'; createdAt = [DateTime]::UtcNow.ToString('o');
        engines = @('reverse', 'ghidra', 'x64dbg'); defaultEngine = 'reverse'; reverseProvider = 'bundled'; builtInProvider = 'ghidra'; publicToolCount = 44;
        includesProjects = $false; files = $records }
    if ($companionObj) {
        $manifest.companionSources = @{ archiveName = $companionObj.archiveName; archiveBytes = [long]$companionObj.archiveBytes; archiveSha256 = $companionObj.archiveSha256 }
    }
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
foreach ($skipped in @($script:IG5SkippedRootFiles | Sort-Object -Unique)) { Write-Output ("SKIPPED_ROOT=" + $skipped) }
$totalBytes = [long]0
foreach ($record in $records) { $totalBytes += [long]$record.bytes }
Write-Output ("BYTES=" + $totalBytes)
