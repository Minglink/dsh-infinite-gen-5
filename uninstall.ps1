<#
  dsh-infinite-gen-5 · 无限五代（IG5 小样）卸载：移除依赖/bundles/Junction/插件目录
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
$pluginName = 'dsh-infinite-gen-5'
$dshRoot = Join-Path $env:USERPROFILE '.dsh'

$profileDirs = @(Get-ChildItem -LiteralPath (Join-Path $dshRoot 'profiles') -Directory -Force -ErrorAction SilentlyContinue |
    Where-Object { Test-Path (Join-Path $_.FullName 'package.json') } |
    ForEach-Object { $_.FullName })

foreach ($pDir in $profileDirs) {
    $pkgPath = Join-Path $pDir 'package.json'
    if (Test-Path $pkgPath) {
        $pkg = Get-Content -LiteralPath $pkgPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($pkg.dependencies -and $pkg.dependencies.PSObject.Properties.Name -contains $pluginName) {
            $pkg.dependencies.PSObject.Properties.Remove($pluginName)
        }
        if ($pkg.dsh -and $pkg.dsh.profile -and $pkg.dsh.profile.bundles) {
            $pkg.dsh.profile.bundles = @($pkg.dsh.profile.bundles | Where-Object { $_ -ne $pluginName })
        }
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($pkgPath, ($pkg | ConvertTo-Json -Depth 10) + [Environment]::NewLine, $utf8NoBom)
        Write-Host "[OK] 已从 $pDir 移除" -ForegroundColor Green
    }
    $nmEntry = Join-Path (Join-Path $pDir 'node_modules') $pluginName
    if (Test-Path $nmEntry) {
        if ((Get-Item $nmEntry).LinkType -eq 'Junction') { cmd.exe /c "rmdir `"$nmEntry`"" 2>$null | Out-Null }
        else { Remove-Item -LiteralPath $nmEntry -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

$plugDir = Join-Path $dshRoot 'plugins\dsh-infinite-gen-5'
if (Test-Path $plugDir) { Remove-Item -LiteralPath $plugDir -Recurse -Force }
Write-Host '卸载完成。重启 DeepSeek Harness 生效。' -ForegroundColor Yellow
