<#
  dsh-infinite-gen-5 · 无限五代（IG5）小样一键安装
  只改动：~\.dsh\plugins\dsh-infinite-gen-5 与各 profile 的 package.json（自动备份）。
  幂等：重复运行安全。安装后完全重启 DeepSeek Harness 生效。
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$pluginName  = 'dsh-infinite-gen-5'
$pluginLabel = '无限五代（IG5）'
$pluginVersion = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'package.json') -Raw -Encoding UTF8 | ConvertFrom-Json).version
$legacyGens  = @('dsh-infinite-gen-1', 'dsh-infinite-gen-2')

function Write-Step { param([string]$m) Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok   { param([string]$m) Write-Host "    [OK] $m" -ForegroundColor Green }
function Write-Warn { param([string]$m) Write-Host "    [!] $m" -ForegroundColor Yellow }
function Write-Err  { param([string]$m) Write-Host "    [X] $m" -ForegroundColor Red }

$dshRoot    = Join-Path $env:USERPROFILE '.dsh'
$pluginsDir = Join-Path $dshRoot 'plugins'
$destDir    = Join-Path $pluginsDir $pluginName
$srcDir     = $PSScriptRoot

Write-Host "`n====================" -ForegroundColor Cyan
Write-Host "  $pluginLabel v$pluginVersion 安装" -ForegroundColor Cyan
Write-Host "====================" -ForegroundColor Cyan

# [1] profile 探测
Write-Step '检查环境'
$profilesRoot = Join-Path $dshRoot 'profiles'
if (-not (Test-Path $profilesRoot)) { Write-Err "未找到 $profilesRoot"; exit 1 }
$profileDirs = @(Get-ChildItem -LiteralPath $profilesRoot -Directory -Force -ErrorAction SilentlyContinue |
    Where-Object { Test-Path (Join-Path $_.FullName 'package.json') } |
    ForEach-Object { $_.FullName })
if ($profileDirs.Count -eq 0) { Write-Err '没有含 package.json 的 profile'; exit 1 }
foreach ($p in $profileDirs) { Write-Ok "profile: $p" }

# [2] 复制插件
Write-Step '复制插件文件'
if (-not (Test-Path $pluginsDir)) { New-Item -ItemType Directory -Path $pluginsDir -Force | Out-Null }
if (Test-Path $destDir) {
    if ((Get-Item $destDir).LinkType -eq 'Junction') { cmd.exe /c "rmdir `"$destDir`"" | Out-Null }
    else { Remove-Item -LiteralPath $destDir -Recurse -Force }
}
robocopy $srcDir $destDir /E /NFL /NDL /NJH /NJS /NC /NS /XD .git __pycache__ | Out-Null
if ($LASTEXITCODE -ge 8) { Write-Err "复制失败（robocopy $LASTEXITCODE）"; exit 1 }
Write-Ok "插件已就位：$destDir"

# [3] 写入各 profile
foreach ($pDir in $profileDirs) {
    $pName = Split-Path $pDir -Leaf
    Write-Step "配置 profile: $pName"
    $pkgPath = Join-Path $pDir 'package.json'
    $bak = "$pkgPath.bak-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Copy-Item -LiteralPath $pkgPath -Destination $bak -Force
    Write-Ok "已备份 package.json"

    $pkg = Get-Content -LiteralPath $pkgPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $pkg.dependencies) { $pkg | Add-Member -NotePropertyName 'dependencies' -NotePropertyValue @{} }
    foreach ($old in $legacyGens) {
        if ($pkg.dependencies.PSObject.Properties.Name -contains $old) {
            $pkg.dependencies.PSObject.Properties.Remove($old)
        }
    }
    if ($pkg.dependencies.PSObject.Properties.Name -notcontains $pluginName) {
        $pkg.dependencies | Add-Member -NotePropertyName $pluginName -NotePropertyValue "file:../../plugins/$pluginName" -Force
    }
    if ($pkg.dsh -and $pkg.dsh.profile -and $pkg.dsh.profile.bundles) {
        $bundles = @($pkg.dsh.profile.bundles)
        foreach ($old in ($legacyGens + @($pluginName))) { $bundles = @($bundles | Where-Object { $_ -ne $old }) }
        $bundles = @($bundles) + $pluginName
        $pkg.dsh.profile.bundles = $bundles
        Write-Ok "bundles 已添加 $pluginName"
    }
    $json = $pkg | ConvertTo-Json -Depth 10
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($pkgPath, $json + [Environment]::NewLine, $utf8NoBom)
    Write-Ok "package.json 已更新（依赖 file:../../plugins/$pluginName）"

    # [4] node_modules Junction 直链（免 pnpm，即改即生效）
    $nmDir  = Join-Path $pDir 'node_modules'
    $nmEntry = Join-Path $nmDir $pluginName
    if (-not (Test-Path $nmDir)) { New-Item -ItemType Directory -Path $nmDir -Force | Out-Null }
    if (Test-Path $nmEntry) {
        try {
            if ((Get-Item $nmEntry).LinkType -eq 'Junction') { cmd.exe /c "rmdir `"$nmEntry`"" 2>$null | Out-Null }
            else { Remove-Item -LiteralPath $nmEntry -Recurse -Force -ErrorAction SilentlyContinue }
        } catch { }
    }
    cmd.exe /c "mklink /J `"$nmEntry`" `"$destDir`"" 2>$null | Out-Null
    if (Test-Path $nmEntry) { Write-Ok "node_modules Junction 就绪：$nmEntry" }
    else { Write-Warn 'Junction 创建失败（可手动复制插件目录到 node_modules）' }

    # [5] 清理旧版残留
    foreach ($old in $legacyGens) {
        $oldNm = Join-Path $nmDir $old
        if (Test-Path $oldNm) { Remove-Item -LiteralPath $oldNm -Recurse -Force -ErrorAction SilentlyContinue }
        $oldPlug = Join-Path $pluginsDir $old
        if (Test-Path $oldPlug) { Remove-Item -LiteralPath $oldPlug -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Write-Step '安装完成'
Write-Host ''
Write-Host '  ✔ 无限五代（IG5）已安装。' -ForegroundColor Green
Write-Host '  下一步：完全退出并重启 DeepSeek Harness（桌面版重新打开 / Web 版重启进程+刷新页面）。' -ForegroundColor White
Write-Host "  验证 1：输入框上方出现状态条「无限五代 $pluginVersion · Reverse」。" -ForegroundColor Yellow
Write-Host '  验证 2：右栏 → 添加 tab → 「IG5 逆向工作台」。' -ForegroundColor Yellow
Write-Host '  验证 3：新会话对模型说「用 ig5_doctor 检查引擎，然后 ig5_open 打开 C:\Windows\System32\notepad.exe」。' -ForegroundColor Yellow
Write-Host ''
