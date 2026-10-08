<#
  IG5 self-contained installer. No downloads, setup scripts or PATH changes.
  Validate the complete runtime before changing the plugin or profile files.
#>
[CmdletBinding()]
param(
    [string]$RuntimeSource,
    [string]$DshRoot = (Join-Path $env:USERPROFILE '.dsh')
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'scripts\runtime_pack.ps1')
$pluginName = 'dsh-infinite-gen-5'
$srcDir = Get-IG5FullPath $PSScriptRoot
$dshRootPath = Get-IG5FullPath $DshRoot
$pluginsDir = Join-Path $dshRootPath 'plugins'
$destDir = Join-Path $pluginsDir $pluginName
$package = Get-Content -LiteralPath (Join-Path $srcDir 'package.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$pluginVersion = [string]$package.version
$legacyGens = @('dsh-infinite-gen-1', 'dsh-infinite-gen-2')
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Assert-Child {
    param([string]$Candidate, [string]$Root)
    $absolute = Get-IG5FullPath $Candidate
    $boundary = (Get-IG5FullPath $Root) + [IO.Path]::DirectorySeparatorChar
    if (-not $absolute.StartsWith($boundary, [StringComparison]::OrdinalIgnoreCase)) { throw "路径超出预期目录: $absolute" }
    return $absolute
}
function Remove-Staging {
    param([string]$Path)
    $safe = Assert-Child $Path $pluginsDir
    if (Test-Path -LiteralPath $safe) {
        if ((Get-Item -LiteralPath $safe).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "暂存目录不能为链接: $safe" }
        Remove-IG5Tree $safe
    }
}

Write-Host "`n无限五代（IG5）v$pluginVersion · 自包含安装" -ForegroundColor Cyan
$runtimeInput = if ($RuntimeSource) { Get-IG5FullPath $RuntimeSource } else { Join-Path $srcDir 'runtimes' }
# Every source and profile check here is read-only. A missing/corrupt pack cannot leave a partial install.
Assert-IG5PluginSource $srcDir
$validated = Assert-IG5RuntimePack $runtimeInput
if ($validated.Manifest.pluginVersion -and [string]$validated.Manifest.pluginVersion -ne $pluginVersion) { throw "运行包版本与插件不符: $($validated.Manifest.pluginVersion) / $pluginVersion" }
$profilesRoot = Join-Path $dshRootPath 'profiles'
if (-not (Test-Path -LiteralPath $profilesRoot -PathType Container)) { throw "未找到 DSH profiles: $profilesRoot" }
$profileDirs = @(Get-ChildItem -LiteralPath $profilesRoot -Directory -Force | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'package.json') -PathType Leaf })
if (-not $profileDirs.Count) { throw '没有含 package.json 的 DSH profile' }
$plans = @()
foreach ($profile in $profileDirs) {
    if ($profile.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "profile 目录不能为链接: $($profile.FullName)" }
    $pkgPath = Join-Path $profile.FullName 'package.json'
    if ([IO.File]::GetAttributes((ConvertTo-IG5IOPath $pkgPath)) -band [IO.FileAttributes]::ReparsePoint) { throw "profile package.json 不能为链接: $pkgPath" }
    $original = [IO.File]::ReadAllText($pkgPath)
    $pkg = $original | ConvertFrom-Json
    if (-not $pkg.dependencies) { $pkg | Add-Member -NotePropertyName dependencies -NotePropertyValue ([pscustomobject]@{}) -Force }
    foreach ($old in $legacyGens) { $pkg.dependencies.PSObject.Properties.Remove($old) }
    $pkg.dependencies | Add-Member -NotePropertyName $pluginName -NotePropertyValue "file:../../plugins/$pluginName" -Force
    if ($pkg.dsh -and $pkg.dsh.profile -and $null -ne $pkg.dsh.profile.bundles) {
        $pkg.dsh.profile.bundles = @(@($pkg.dsh.profile.bundles) | Where-Object { $_ -notin ($legacyGens + @($pluginName)) }) + @($pluginName)
    }
    $plans += [pscustomobject]@{ Directory=$profile.FullName; Path=$pkgPath; Original=$original; Json=($pkg | ConvertTo-Json -Depth 100 -WarningAction Stop) + [Environment]::NewLine }
}
$destDir = Assert-Child $destDir $pluginsDir
if ($srcDir -eq $destDir -or $srcDir.StartsWith($destDir + '\', [StringComparison]::OrdinalIgnoreCase) -or $destDir.StartsWith($srcDir + '\', [StringComparison]::OrdinalIgnoreCase)) { throw '安装源与插件目的目录不能相同或相互包含' }
if (Test-Path -LiteralPath $pluginsDir) { if ((Get-Item -LiteralPath $pluginsDir).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'plugins 目录不能为链接' } }
if (Test-Path -LiteralPath $destDir) { if ((Get-Item -LiteralPath $destDir).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw '插件目的目录不能为链接' } }
foreach ($plan in $plans) {
    $nm = Join-Path $plan.Directory 'node_modules'
    if ((Test-Path -LiteralPath $nm) -and ((Get-Item -LiteralPath $nm).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "node_modules 不能为链接: $nm" }
}
Write-Host "[OK] 两引擎完整性验证通过：$($validated.Files) 个文件" -ForegroundColor Green

$token = [Guid]::NewGuid().ToString('N')
$stage = Assert-Child (Join-Path $pluginsDir ".ig5-stage-$token") $pluginsDir
$previous = Assert-Child (Join-Path $pluginsDir ".ig5-previous-$token") $pluginsDir
$switched = $false
$movedPrevious = $false
$records = @()
try {
    New-Item -ItemType Directory -Path $pluginsDir -Force | Out-Null
    # Stage and verify a complete plugin before replacing a prior installation.
    Copy-IG5Pack $srcDir $stage @('runtimes')
    Copy-IG5Pack $runtimeInput (Join-Path $stage 'runtimes')
    Write-IG5RuntimeManifest $validated (Join-Path $stage 'runtimes') $pluginVersion
    $null = Assert-IG5RuntimePack (Join-Path $stage 'runtimes')
    if (Test-Path -LiteralPath $destDir) { Move-Item -LiteralPath $destDir -Destination $previous; $movedPrevious = $true }
    Move-Item -LiteralPath $stage -Destination $destDir
    $switched = $true
    foreach ($plan in $plans) {
        $nm = Join-Path $plan.Directory 'node_modules'
        $entry = Assert-Child (Join-Path $nm $pluginName) $nm
        $savedEntry = Assert-Child (Join-Path $nm ".ig5-entry-$token") $nm
        $backup = "$($plan.Path).bak-$token"
        $record = [pscustomobject]@{ Plan=$plan; Entry=$entry; Saved=$savedEntry; OldEntry=$false; NewEntry=$false; Written=$false }
        $records += $record
        Copy-Item -LiteralPath $plan.Path -Destination $backup
        New-Item -ItemType Directory -Path $nm -Force | Out-Null
        if (Get-Item -LiteralPath $entry -Force -ErrorAction SilentlyContinue) { Move-Item -LiteralPath $entry -Destination $savedEntry; $record.OldEntry = $true }
        New-Item -ItemType Junction -Path $entry -Target $destDir | Out-Null
        $record.NewEntry = $true
        $temporary = "$($plan.Path).ig5-$token"
        [IO.File]::WriteAllText($temporary, $plan.Json, $utf8NoBom)
        Move-Item -LiteralPath $temporary -Destination $plan.Path -Force
        $record.Written = $true
        Write-Host "[OK] profile: $(Split-Path $plan.Directory -Leaf)" -ForegroundColor Green
    }
    if ($movedPrevious) {
        $backupRoot = Join-Path $dshRootPath 'ig5\artifacts'
        New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
        Move-Item -LiteralPath $previous -Destination (Join-Path $backupRoot "install-backup-$token")
        $movedPrevious = $false
    }
} catch {
    $failure = $_
    foreach ($record in $records) {
        if ($record.Written) { [IO.File]::WriteAllText($record.Plan.Path, $record.Plan.Original, $utf8NoBom) }
        if ($record.NewEntry -and (Get-Item -LiteralPath $record.Entry -Force -ErrorAction SilentlyContinue)) { [IO.Directory]::Delete($record.Entry) }
        if ($record.OldEntry -and (Get-Item -LiteralPath $record.Saved -Force -ErrorAction SilentlyContinue)) { Move-Item -LiteralPath $record.Saved -Destination $record.Entry }
    }
    if ($switched) { Remove-Staging $destDir }
    if ($movedPrevious) { Move-Item -LiteralPath $previous -Destination $destDir }
    if (Test-Path -LiteralPath $stage) { Remove-Staging $stage }
    throw $failure
}
foreach ($record in $records) {
    # Once committed, cleanup cannot roll back the new plugin or erase its backup.
    try {
        if ($record.OldEntry -and (Get-Item -LiteralPath $record.Saved -Force).LinkType -eq 'Junction') { [IO.Directory]::Delete($record.Saved) }
    } catch { Write-Warning "旧 Junction 保留供手动清理: $($record.Saved)" }
}
Write-Host "`n[OK] 无限五代（IG5）已安装：$destDir" -ForegroundColor Green
Write-Host '完整 Ghidra / x64dbg 能力随插件就位；无需运行 setup 脚本或修改系统 PATH。'
Write-Host '完全退出并重启 DeepSeek Harness，然后调用 ig5_doctor 检查。'
