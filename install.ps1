<#
  IG5 self-contained installer. Full releases install offline.
  Source ZIPs supplement pinned distribution assets without replacing source code.
  Validate the complete runtime before changing the plugin or profile files.
#>
[CmdletBinding()]
param(
    [string]$RuntimeSource,
    [string]$DistributionRoot,
    [string]$DistributionArchive,
    [switch]$RepairAssets,
    [switch]$Offline,
    [string]$DshRoot = (Join-Path $env:USERPROFILE '.dsh')
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'scripts\runtime_pack.ps1')
. (Join-Path $PSScriptRoot 'scripts\bootstrap_distribution.ps1')
$pluginName = 'dsh-infinite-gen-5'
$srcDir = Get-IG5FullPath $PSScriptRoot
$sourceInput = $srcDir
$dshRootPath = Get-IG5FullPath $DshRoot
$pluginsDir = Join-Path $dshRootPath 'plugins'
$destDir = Join-Path $pluginsDir $pluginName
$package = Get-Content -LiteralPath (Join-Path $srcDir 'package.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$pluginVersion = [string]$package.version
if ($package.name -cne $pluginName -or -not $pluginVersion) { throw 'Plugin package identity/version is invalid' }
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

$bootstrap = $null
try {
Write-Host "`n无限五代（IG5）v$pluginVersion · 自包含安装" -ForegroundColor Cyan
Assert-IG5NoReparsePath $dshRootPath
Assert-IG5NoReparsePath (Join-Path $dshRootPath 'profiles')
Assert-IG5NoReparsePath $pluginsDir
Assert-IG5NoReparsePath (Join-Path $dshRootPath 'ig5\artifacts')
Assert-IG5PluginSource $srcDir -CoreOnly
if ($DistributionRoot -and $DistributionArchive) { throw 'Choose either DistributionRoot or DistributionArchive, not both' }
if ($RepairAssets -and $RuntimeSource) { throw 'RepairAssets cannot be combined with RuntimeSource' }
# Bootstrap only a clean source-only tree. A partial/damaged full pack must fail closed.
$sourceOnly = -not (Test-IG5Path (Join-Path $srcDir 'runtimes')) -and -not (Test-IG5Path (Join-Path $srcDir 'third_party\sources')) -and -not (Test-IG5Path (Join-Path (Split-Path $srcDir -Parent) 'manifest.json'))
# Freeze expected core records before profiles or long donor/download work. Full
# repair retains the authenticated outer inventory; source-only installs retain
# their own initial code. Never accept a later snapshot as the new baseline.
$coreFiles = if ($RepairAssets -and -not $sourceOnly) { @(Assert-IG5ReleaseCore $srcDir $pluginVersion) } else { @(Get-IG5CoreInventory $srcDir) }
# Every source and profile check here is read-only. A missing/corrupt pack cannot leave a partial install.
$profilesRoot = Join-Path $dshRootPath 'profiles'
if (-not (Test-Path -LiteralPath $profilesRoot -PathType Container)) { throw "未找到 DSH profiles: $profilesRoot" }
$profileDirs = @(Get-ChildItem -LiteralPath $profilesRoot -Directory -Force | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'package.json') -PathType Leaf })
if (-not $profileDirs.Count) { throw '没有含 package.json 的 DSH profile' }
$plans = @()
foreach ($profile in $profileDirs) {
    if ($profile.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "profile 目录不能为链接: $($profile.FullName)" }
    $pkgPath = Join-Path $profile.FullName 'package.json'
    if ([IO.File]::GetAttributes((ConvertTo-IG5IOPath $pkgPath)) -band [IO.FileAttributes]::ReparsePoint) { throw "profile package.json 不能为链接: $pkgPath" }
    $originalBytes = [IO.File]::ReadAllBytes($pkgPath)
    $reader = [IO.StreamReader]::new([IO.MemoryStream]::new($originalBytes), [Text.Encoding]::UTF8, $true)
    try { $original = $reader.ReadToEnd() } finally { $reader.Dispose() }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $originalHash = [BitConverter]::ToString($sha.ComputeHash($originalBytes)).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
    if ((Get-IG5Hash $pkgPath) -ne $originalHash) { throw "Profile changed during preflight: $pkgPath" }
    $pkg = $original | ConvertFrom-Json
    if (-not $pkg.dependencies) { $pkg | Add-Member -NotePropertyName dependencies -NotePropertyValue ([pscustomobject]@{}) -Force }
    foreach ($old in $legacyGens) { $pkg.dependencies.PSObject.Properties.Remove($old) }
    $pkg.dependencies | Add-Member -NotePropertyName $pluginName -NotePropertyValue "file:../../plugins/$pluginName" -Force
    if ($pkg.dsh -and $pkg.dsh.profile -and $null -ne $pkg.dsh.profile.bundles) {
        $pkg.dsh.profile.bundles = @(@($pkg.dsh.profile.bundles) | Where-Object { $_ -notin ($legacyGens + @($pluginName)) }) + @($pluginName)
    }
    $plans += [pscustomobject]@{ Directory=$profile.FullName; Path=$pkgPath; Original=$original; OriginalBytes=$originalBytes; OriginalHash=$originalHash; Json=($pkg | ConvertTo-Json -Depth 100 -WarningAction Stop) + [Environment]::NewLine }
}
$destDir = Assert-Child $destDir $pluginsDir
foreach ($inputDir in @($srcDir, $sourceInput)) {
    if ($inputDir -eq $destDir -or $inputDir.StartsWith($destDir + '\', [StringComparison]::OrdinalIgnoreCase) -or $destDir.StartsWith($inputDir + '\', [StringComparison]::OrdinalIgnoreCase)) { throw '安装源与插件目的目录不能相同或相互包含' }
}
if (Test-Path -LiteralPath $pluginsDir) { if ((Get-Item -LiteralPath $pluginsDir).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'plugins 目录不能为链接' } }
if (Test-Path -LiteralPath $destDir) { if ((Get-Item -LiteralPath $destDir).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw '插件目的目录不能为链接' } }
foreach ($plan in $plans) {
    $nm = Join-Path $plan.Directory 'node_modules'
    if ((Test-Path -LiteralPath $nm) -and ((Get-Item -LiteralPath $nm).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "node_modules 不能为链接: $nm" }
}
if ($sourceOnly -or $RepairAssets) {
    $prepareArgs = @{SourceRoot=$srcDir;PluginVersion=$pluginVersion;DistributionRoot=$DistributionRoot;Offline=$Offline;CoreFiles=$coreFiles}
    if ($DistributionArchive) { $prepareArgs.DistributionArchive = $DistributionArchive }
    $bootstrap = New-IG5SourceDistribution @prepareArgs
    $srcDir = $bootstrap.Root
} elseif ($DistributionRoot -or $DistributionArchive) { throw 'Full-package asset recovery requires -RepairAssets; changed core code remains rejected.' }
$runtimeInput = if ($RuntimeSource) { Get-IG5FullPath $RuntimeSource } else { Join-Path $srcDir 'runtimes' }
Assert-IG5PluginSource $srcDir
Assert-IG5FileInventory $srcDir $coreFiles 'core-after-preparation' -IgnoredPrefixes @('runtimes/','third_party/sources/')
$validated = Assert-IG5RuntimePack $runtimeInput
if ($validated.Manifest.pluginVersion -and [string]$validated.Manifest.pluginVersion -ne $pluginVersion) { throw "运行包版本与插件不符: $($validated.Manifest.pluginVersion) / $pluginVersion" }
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
    Assert-IG5FileInventory $stage $coreFiles 'staged-core' -IgnoredPrefixes @('runtimes/','third_party/sources/')
    if ($bootstrap -and -not $RuntimeSource) {
        Assert-IG5PluginSource $stage -CoreOnly
        $stageDescriptor = Get-IG5DistributionDescriptor $stage $pluginVersion
        $null = Assert-IG5PinnedAssets $stage $stageDescriptor $pluginVersion
    } else {
        $null = Assert-IG5RuntimePack (Join-Path $stage 'runtimes')
        Assert-IG5PluginSource $stage
    }
    # Downloads, extraction and staging can take minutes. Never overwrite a changed profile plan.
    Assert-IG5NoReparsePath $destDir
    Assert-IG5NoReparsePath (Join-Path $dshRootPath 'ig5\artifacts')
    foreach ($plan in $plans) {
        Assert-IG5NoReparsePath $plan.Path
        Assert-IG5NoReparsePath (Join-Path $plan.Directory 'node_modules')
        if (-not (Test-IG5Path $plan.Path Leaf) -or (Get-IG5Hash $plan.Path) -ne $plan.OriginalHash) { throw "Profile changed during preparation; rerun installation: $($plan.Path)" }
    }
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
        if ((Get-IG5Hash $plan.Path) -ne $plan.OriginalHash) { throw "Profile changed during commit; rerun installation: $($plan.Path)" }
        [IO.File]::WriteAllBytes($backup, $plan.OriginalBytes)
        New-Item -ItemType Directory -Path $nm -Force | Out-Null
        if (Get-Item -LiteralPath $entry -Force -ErrorAction SilentlyContinue) { Move-Item -LiteralPath $entry -Destination $savedEntry; $record.OldEntry = $true }
        New-Item -ItemType Junction -Path $entry -Target $destDir | Out-Null
        $record.NewEntry = $true
        foreach ($runtimeEntry in @('ghidra','x64dbg')) {
            $projected = Join-Path $entry "runtimes\$runtimeEntry\runtime.json"
            $physical = Join-Path $destDir "runtimes\$runtimeEntry\runtime.json"
            if (-not (Test-IG5Path $projected Leaf) -or (Get-IG5Hash $projected) -ne (Get-IG5Hash $physical)) { throw "Profile entry cannot read the installed $runtimeEntry runtime; profile registration aborted" }
        }
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
        if ($record.Written) { [IO.File]::WriteAllBytes($record.Plan.Path, $record.Plan.OriginalBytes) }
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
} finally {
    if ($bootstrap) { Remove-IG5BootstrapWorkspace $bootstrap.Workspace }
}
