<# Uninstall only this plugin; preserve projects, runtime state, other plugins and profile backups. #>
[CmdletBinding()]
param([string]$DshRoot = (Join-Path $env:USERPROFILE '.dsh'))
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'scripts\runtime_pack.ps1')
$pluginName = 'dsh-infinite-gen-5'
$root = Get-IG5FullPath $DshRoot
$profiles = Join-Path $root 'profiles'
$plugins = Join-Path $root 'plugins'
$plugin = Join-Path $plugins $pluginName
$utf8 = [Text.UTF8Encoding]::new($false)
$token = [Guid]::NewGuid().ToString('N')
$plans = @()
foreach ($path in @($profiles, $plugins, $plugin)) {
    if ((Test-IG5Path $path) -and ([IO.File]::GetAttributes((ConvertTo-IG5IOPath $path)) -band [IO.FileAttributes]::ReparsePoint)) { throw "卸载目录不能为链接: $path" }
}
# Parse every profile before writing anything. Bad JSON must never become a null package.json.
if (Test-IG5Path $profiles Container) {
    foreach ($directory in (New-Object IO.DirectoryInfo (ConvertTo-IG5IOPath $profiles)).GetDirectories()) {
        $profileDir = Get-IG5FullPath $directory.FullName
        $file = Join-Path $profileDir 'package.json'
        if (-not (Test-IG5Path $file Leaf)) { continue }
        if ([IO.File]::GetAttributes((ConvertTo-IG5IOPath $file)) -band [IO.FileAttributes]::ReparsePoint) { throw "profile package.json 不能为链接: $file" }
        if ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "profile 不能为链接: $profileDir" }
        $text = Read-IG5Text $file
        try { $pkg = $text | ConvertFrom-Json -ErrorAction Stop }
        catch { throw "profile JSON 无效，未执行卸载: $file" }
        if (-not $pkg -or $pkg -is [array] -or $pkg -is [string] -or $pkg -is [ValueType]) { throw "profile 必须是 JSON 对象，未执行卸载: $file" }
        if ($pkg.dependencies) { $pkg.dependencies.PSObject.Properties.Remove($pluginName) }
        if ($pkg.dsh -and $pkg.dsh.profile -and $null -ne $pkg.dsh.profile.bundles) { $pkg.dsh.profile.bundles = @($pkg.dsh.profile.bundles | Where-Object { $_ -ne $pluginName }) }
        $nm = Join-Path $profileDir 'node_modules'
        if ((Test-IG5Path $nm) -and ([IO.File]::GetAttributes((ConvertTo-IG5IOPath $nm)) -band [IO.FileAttributes]::ReparsePoint)) { throw "node_modules 不能为链接: $nm" }
        $plans += [pscustomobject]@{Path=$file;Original=$text;Json=($pkg | ConvertTo-Json -Depth 100 -WarningAction Stop) + [Environment]::NewLine;Entry=(Join-Path $nm $pluginName)}
    }
}
$written = @()
try {
    foreach ($plan in $plans) {
        [IO.File]::Copy((ConvertTo-IG5IOPath $plan.Path), (ConvertTo-IG5IOPath "$($plan.Path).bak-uninstall-$token"), $false)
        [IO.File]::WriteAllText((ConvertTo-IG5IOPath $plan.Path), $plan.Json, $utf8)
        $written += $plan
    }
} catch {
    foreach ($plan in $written) { [IO.File]::WriteAllText((ConvertTo-IG5IOPath $plan.Path), $plan.Original, $utf8) }
    throw
}
foreach ($plan in $plans) {
    if (Test-IG5Path $plan.Entry) {
        $attributes = [IO.File]::GetAttributes((ConvertTo-IG5IOPath $plan.Entry))
        if ($attributes -band [IO.FileAttributes]::ReparsePoint) {
            # Remove only the link, never its target tree.
            if ($attributes -band [IO.FileAttributes]::Directory) { [IO.Directory]::Delete((ConvertTo-IG5IOPath $plan.Entry), $false) }
            else { [IO.File]::Delete((ConvertTo-IG5IOPath $plan.Entry)) }
        } else {
            # An unexpected physical node_modules entry may contain local work. Preserve it.
            $saved = "$($plan.Entry).bak-uninstall-$token"
            if ($attributes -band [IO.FileAttributes]::Directory) { [IO.Directory]::Move((ConvertTo-IG5IOPath $plan.Entry), (ConvertTo-IG5IOPath $saved)) }
            else { [IO.File]::Move((ConvertTo-IG5IOPath $plan.Entry), (ConvertTo-IG5IOPath $saved)) }
        }
    }
}
$safe = Resolve-IG5PackPath $plugins $pluginName
if ($safe -ne (Get-IG5FullPath $plugin)) { throw '卸载目标校验失败' }
Remove-IG5Tree $safe
Write-Host '[OK] IG5 已卸载。用户 projects/state/artifacts、其他插件及备份均保留；重启 DeepSeek Harness 生效。' -ForegroundColor Green
