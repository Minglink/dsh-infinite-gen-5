# Shared, read-only runtime validation for installation and portable packaging.
$script:IG5RuntimeCaches = @('downloads', 'sessions', 'projects', 'native-build', 'toolchain', 'clientdeps', '.cache', '__pycache__')
# The plugin source root may only ship these top-level files. Directory traversal
# skips any other root file (local sample copies, logs, build outputs), so a stray
# artifact cannot ride into a portable package just because no denylist rule names
# it. Unlisted code-like extensions fail loudly instead of being dropped silently.
$script:IG5PackRootFiles = @(
    '.gitattributes', '.gitignore', 'AGENTS.md', 'HARNESS_PLUGIN.md', 'LICENSE', 'README.md',
    'THIRD_PARTY_NOTICES.txt', 'advanced_tools.js', 'analysis_tools.js', 'capture_tools.js', 'client.js',
    'cordis.patch.yml', 'engine_runtime.js', 'index.js', 'install.ps1', 'integration_tools.js',
    'package.json', 'semantic_diff.js', 'semantic_diff_async.js', 'semantic_diff_worker.js',
    'uninstall.ps1', 'workflow.js'
)
$script:IG5SkippedRootFiles = New-Object 'System.Collections.Generic.List[string]'

function Get-IG5FullPath {
    param([Parameter(Mandatory)][string]$Path)
    if ($env:OS -ne 'Windows_NT') { return [IO.Path]::GetFullPath($Path).TrimEnd('/') }
    $value = $Path.Replace('/', '\')
    if ($value.StartsWith('\\?\UNC\')) { $value = '\\' + $value.Substring(8) }
    elseif ($value.StartsWith('\\?\')) { $value = $value.Substring(4) }
    if ($value -notmatch '^(?:[A-Za-z]:\\|\\\\[^\\]+\\[^\\]+(?:\\|$))') { $value = (Get-Location).ProviderPath.TrimEnd('\') + '\' + $value }
    $rootMatch = [regex]::Match($value, '^(?:[A-Za-z]:\\|\\\\[^\\]+\\[^\\]+(?:\\|$))')
    if (-not $rootMatch.Success) { throw "无效绝对路径: $Path" }
    $rootPart = $rootMatch.Value.TrimEnd('\') + '\'
    $parts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($part in $value.Substring($rootMatch.Length).Split('\')) {
        if (-not $part -or $part -eq '.') { continue }
        if ($part -eq '..') { if ($parts.Count) { $parts.RemoveAt($parts.Count - 1) }; continue }
        $parts.Add($part)
    }
    if (-not $parts.Count) { return $rootPart }
    return $rootPart + ($parts -join '\')
}

function ConvertTo-IG5IOPath {
    param([string]$Path)
    $full = Get-IG5FullPath $Path
    if ($env:OS -ne 'Windows_NT') { return $full }
    if ($full.StartsWith('\\')) { return '\\?\UNC\' + $full.Substring(2) }
    return '\\?\' + $full
}
function Test-IG5Path {
    param([string]$Path, [ValidateSet('Any','Leaf','Container')][string]$PathType='Any')
    $io = ConvertTo-IG5IOPath $Path
    if ($PathType -eq 'Leaf') { return [IO.File]::Exists($io) }
    if ($PathType -eq 'Container') { return [IO.Directory]::Exists($io) }
    return [IO.File]::Exists($io) -or [IO.Directory]::Exists($io)
}
function Get-IG5Hash {
    param([string]$Path)
    $stream = [IO.File]::OpenRead((ConvertTo-IG5IOPath $Path))
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose(); $stream.Dispose() }
}
function Read-IG5Text { param([string]$Path) return [IO.File]::ReadAllText((ConvertTo-IG5IOPath $Path), [Text.Encoding]::UTF8) }

function Assert-IG5NoReparsePath {
    param([string]$Path)
    $candidate = Get-IG5FullPath $Path
    while ($candidate) {
        if ((Test-IG5Path $candidate) -and ([IO.File]::GetAttributes((ConvertTo-IG5IOPath $candidate)) -band [IO.FileAttributes]::ReparsePoint)) { throw "Path ancestor cannot be a link: $candidate" }
        $parent = Split-Path $candidate -Parent
        if (-not $parent -or $parent -eq $candidate) { break }
        $candidate = $parent
    }
}

function Remove-IG5Tree {
    param([Parameter(Mandatory)][string]$Path)
    $io = ConvertTo-IG5IOPath $Path
    if (-not (Test-IG5Path $Path)) { return }
    $attributes = [IO.File]::GetAttributes($io)
    if ($attributes -band [IO.FileAttributes]::Directory) {
        if (-not ($attributes -band [IO.FileAttributes]::ReparsePoint)) {
            foreach ($child in (New-Object IO.DirectoryInfo $io).GetFileSystemInfos()) { Remove-IG5Tree $child.FullName }
        }
        [IO.Directory]::Delete($io, $false)
    } else {
        if ($attributes -band [IO.FileAttributes]::ReadOnly) { [IO.File]::SetAttributes($io, ($attributes -band (-bnot [IO.FileAttributes]::ReadOnly))) }
        [IO.File]::Delete($io)
    }
}

function Resolve-IG5PackPath {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Relative)
    if ([IO.Path]::IsPathRooted($Relative) -or $Relative -match '(^|[\\/])\.\.([\\/]|$)' -or $Relative.Contains(':')) {
        throw "运行包路径必须为包内相对路径: $Relative"
    }
    $base = Get-IG5FullPath $Root
    $full = Get-IG5FullPath ($base + [IO.Path]::DirectorySeparatorChar + $Relative)
    if (-not $full.StartsWith($base + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "运行包路径超出根目录: $Relative"
    }
    return $full
}

function Test-IG5VersionAtLeast {
    param([string]$Version, [string]$Minimum)
    if ($Version -notmatch '^\d+\.\d+\.\d+$' -or $Minimum -notmatch '^\d+\.\d+\.\d+$') { return $false }
    return ([Version]::new($Version) -ge [Version]::new($Minimum))
}

function Get-IG5SampleSpecificFiles {
    param([Parameter(Mandatory)][string]$SourceRoot)
    $manifestPath = Join-Path $SourceRoot 'tools\ci\sample-specific.json'
    if (-not (Test-IG5Path $manifestPath Leaf)) { return @() }
    $data = Read-IG5Text $manifestPath | ConvertFrom-Json
    return @($data.files | ForEach-Object { ([string]$_).Replace('\', '/').ToLowerInvariant() })
}

function Test-IG5ExcludedPath {
    param(
        [string]$Relative,
        [switch]$RuntimeRoot,
        [switch]$PortableRelease,
        [string[]]$SampleSpecificFiles = @()
    )
    $norm = $Relative.Replace('\', '/')
    $parts = $norm.Split('/')
    if ($parts -contains '.git') { return $true }
    if ($parts[0] -eq 'plugin') { $parts = @($parts | Select-Object -Skip 1); $norm = ($parts -join '/') }
    if ($parts[0] -eq '.downloads') { return $true }
    if ($parts[0] -eq 'scratch') { return $true }
    if ($parts.Count -eq 4 -and $parts[0] -eq 'adapters' -and $parts[1] -eq 'vmci' -and $parts[2] -eq 'native' -and $parts[3] -like '*.obj') { return $true }
    # Vendored upstream source trees retain every source path except their Git metadata.
    if ($parts.Count -ge 2 -and $parts[0] -eq 'third_party' -and $parts[1] -eq 'sources') { return $false }
    if ($parts -contains '__pycache__' -or $parts -contains '.pytest_cache' -or $parts -contains 'node_modules') { return $true }
    if ($parts[0] -eq 'runtimes') { $parts = @($parts | Select-Object -Skip 1); $RuntimeRoot = $true }
    if ($RuntimeRoot -and $parts.Count -ge 2 -and $parts[0] -in @('ghidra','x64dbg') -and $parts[1] -in $script:IG5RuntimeCaches) { return $true }
    if ($PortableRelease -and -not $RuntimeRoot) {
        if ($parts[0] -eq 'archive') { return $true }
        if ($parts.Count -ge 2 -and $parts[0] -eq 'docs' -and $parts[1] -eq 'review') { return $true }
        if ($parts.Count -ge 2 -and $parts[0] -eq 'scripts' -and ($parts[1] -like 'test_*' -or $parts[1] -like 'accept_*')) { return $true }
        if ($SampleSpecificFiles.Count -and ($SampleSpecificFiles -contains $norm.ToLowerInvariant())) { return $true }
    }
    return $false
}

function Get-IG5PackFiles {
    param(
        [Parameter(Mandatory)][string]$Root,
        [switch]$IncludeExcluded,
        [switch]$IncludeUnlistedRootFiles,
        [switch]$PortableRelease,
        [string[]]$SampleSpecificFiles = @(),
        [string[]]$ExtraExclude = @()
    )
    $base = Get-IG5FullPath $Root
    $isRuntime = (Test-IG5Path (Join-Path $base 'ghidra\runtime.json')) -or (Test-IG5Path (Join-Path $base 'x64dbg\runtime.json'))
    $isPluginRoot = -not $isRuntime -and (Test-IG5Path (Join-Path $base 'package.json') Leaf) -and (Test-IG5Path (Join-Path $base 'index.js') Leaf)
    $isSourceTree = $base -match '(^|[\\/])third_party[\\/]sources(?:[\\/]|$)'
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    $pending.Push($base)
    while ($pending.Count) {
        $dir = $pending.Pop()
        $directoryInfo = New-Object IO.DirectoryInfo (ConvertTo-IG5IOPath $dir)
        foreach ($entry in $directoryInfo.GetFileSystemInfos()) {
            $relative = Get-IG5RelativePath $base $entry.FullName
            if ($ExtraExclude.Count) {
                $skipExtra = $false
                foreach ($excluded in $ExtraExclude) {
                    $trimEx = $excluded.TrimEnd('/')
                    if ($relative.Equals($trimEx, [StringComparison]::OrdinalIgnoreCase) -or $relative.StartsWith($trimEx + '/', [StringComparison]::OrdinalIgnoreCase)) { $skipExtra = $true; break }
                }
                if ($skipExtra) { continue }
            }
            $filterPath = if ($isSourceTree) { 'third_party/sources/' + $relative } else { $relative }
            if (-not $IncludeExcluded -and (Test-IG5ExcludedPath $filterPath -RuntimeRoot:$isRuntime -PortableRelease:$PortableRelease -SampleSpecificFiles $SampleSpecificFiles)) { continue }
            if (-not $IncludeExcluded -and -not $IncludeUnlistedRootFiles -and $isPluginRoot -and $entry -isnot [IO.DirectoryInfo] -and $relative.IndexOf('/') -lt 0 -and $script:IG5PackRootFiles -notcontains $relative) {
                if ($relative -match '\.(?:js|mjs|cjs|json|ps1|psm1|ya?ml)$') { throw "Unexpected plugin root file; add it to IG5PackRootFiles or move it out of the source tree: $relative" }
                $script:IG5SkippedRootFiles.Add($relative)
                continue
            }
            if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "发行目录不能含链接: $($entry.FullName)" }
            if ($entry -is [IO.DirectoryInfo]) { $pending.Push((Get-IG5FullPath $entry.FullName)) }
            else { [pscustomobject]@{Name=$entry.Name;FullName=(Get-IG5FullPath $entry.FullName);Length=$entry.Length;Attributes=$entry.Attributes} }
        }
    }
}

function Get-IG5RelativePath {
    param([string]$Root, [string]$Path)
    $base = (Get-IG5FullPath $Root) + [IO.Path]::DirectorySeparatorChar
    $full = Get-IG5FullPath $Path
    if (-not $full.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) { throw "文件超出根目录: $full" }
    return $full.Substring($base.Length).Replace('\', '/')
}

function Assert-IG5RuntimeExtensions {
    param([Parameter(Mandatory)][string]$Root)
    # New optional runtimes have independent fixed manifests. Never rewrite the
    # original ghidra/x64dbg donor manifest or silently accept arbitrary extras.
    $pins = @{
        mergen = @{ manifest='manifest.json'; sha256='1d63bc53c0a0f49e99163768d716727a4ea02056b4617165c18db20e21b28485' }
        scyllahide = @{ manifest='ig5-manifest.json'; sha256='d6e2bb2f6c1ecb4a59a54a80c21a9475561b0fa877dbdc7b2a9c44e90d865a82' }
    }
    $records = @{}
    foreach ($name in $pins.Keys) {
        $directory = Join-Path $Root $name
        if (-not (Test-IG5Path $directory)) { continue }
        $manifestPath = Resolve-IG5PackPath $directory $pins[$name].manifest
        if (-not (Test-IG5Path $manifestPath Leaf) -or (Get-IG5Hash $manifestPath) -cne $pins[$name].sha256) { throw "Optional runtime manifest pin mismatch: $name" }
        $manifest = Read-IG5Text $manifestPath | ConvertFrom-Json
        $rows = @($manifest.files)
        if ($rows.Count -lt 1 -or $rows.Count -gt 32) { throw "Optional runtime inventory budget invalid: $name" }
        $local = @{}
        foreach ($row in $rows) {
            $relative = [string]$row.path
            if ($relative -notmatch '^[A-Za-z0-9_.-]+$' -or $relative -eq '.' -or $relative -eq '..' -or $relative -eq $pins[$name].manifest -or $local.ContainsKey($relative)) { throw "Optional runtime path invalid: $name" }
            $file = Resolve-IG5PackPath $directory $relative
            if (-not (Test-IG5Path $file Leaf) -or (New-Object IO.FileInfo (ConvertTo-IG5IOPath $file)).Length -ne [long]$row.bytes -or (Get-IG5Hash $file) -cne [string]$row.sha256) { throw "Optional runtime file pin mismatch: $name/$relative" }
            $local[$relative] = $true
            $records["$name/$relative"] = $row
        }
        $actual = @(Get-IG5PackFiles $directory)
        if ($actual.Count -ne $rows.Count + 1) { throw "Optional runtime contains unregistered files: $name" }
        foreach ($file in $actual) {
            $relative = Get-IG5RelativePath $directory $file.FullName
            if ($relative -ne $pins[$name].manifest -and -not $local.ContainsKey($relative)) { throw "Optional runtime contains unregistered files: $name/$relative" }
        }
        $records["$name/$($pins[$name].manifest)"] = @{path=$pins[$name].manifest;bytes=(New-Object IO.FileInfo (ConvertTo-IG5IOPath $manifestPath)).Length;sha256=$pins[$name].sha256}
    }
    return $records
}

function Assert-IG5RuntimePack {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root)
    $base = Get-IG5FullPath $Root
    if (-not (Test-IG5Path $base Container)) { throw "缺少自包含运行目录: $base" }
    if ([IO.File]::GetAttributes((ConvertTo-IG5IOPath $base)) -band [IO.FileAttributes]::ReparsePoint) { throw "运行目录不能为链接: $base" }
    $manifestPath = Join-Path $base 'manifest.json'
    $prefix = ''
    if (-not (Test-IG5Path $manifestPath Leaf)) {
        # v0.x portable packs kept runtimes beside plugin and listed them in the parent manifest.
        $legacy = Join-Path (Split-Path $base -Parent) 'manifest.json'
        if (-not (Test-IG5Path $legacy Leaf)) { throw "缺少完整 SHA-256 清单: $manifestPath" }
        $manifestPath = $legacy
        $prefix = (Split-Path $base -Leaf) + '/'
    }
    try { $manifest = Read-IG5Text $manifestPath | ConvertFrom-Json }
    catch { throw "运行包清单 JSON 无效: $manifestPath ($($_.Exception.Message))" }
    if ($manifest.schemaVersion -ne 1 -or $manifest.platform -ne 'win32-x64' -or -not $manifest.files) { throw "运行包清单 schema/platform/files 无效: $manifestPath" }
    $runtimeTotal = @($manifest.files).Count
    $runtimeProgress = $runtimeTotal -ge 4096
    if ($runtimeProgress) { Write-Host "[VERIFY] runtime: $runtimeTotal inventory entries; checking required components and hashes..." }
    foreach ($engine in @('ghidra', 'x64dbg')) { if (@($manifest.engines) -notcontains $engine) { throw "清单缺少引擎: $engine" } }
    $records = @{}
    foreach ($record in $manifest.files) {
        $relative = [string]$record.path
        if ($prefix) {
            if (-not $relative.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { continue }
            $relative = $relative.Substring($prefix.Length)
        }
        $relative = $relative.Replace('\', '/')
        $full = Resolve-IG5PackPath $base $relative
        if ($relative -eq 'manifest.json' -or (Test-IG5ExcludedPath $relative -RuntimeRoot)) { throw "清单不能包含自身或运行缓存: $relative" }
        if ($records.ContainsKey($relative)) { throw "清单重复路径: $relative" }
        if ([string]$record.sha256 -notmatch '^[a-fA-F0-9]{64}$' -or [long]$record.bytes -lt 0) { throw "清单 SHA-256/bytes 无效: $relative" }
        if (-not (Test-IG5Path $full Leaf)) { throw "运行包缺少文件: $relative" }
        if ((New-Object IO.FileInfo (ConvertTo-IG5IOPath $full)).Length -ne [long]$record.bytes) { throw "运行包文件长度不符: $relative" }
        $records[$relative] = $record
    }
    foreach ($engine in @('ghidra', 'x64dbg')) {
        $configPath = Join-Path $base "$engine\runtime.json"
        if (-not (Test-IG5Path $configPath Leaf)) { throw "缺少引擎清单: $engine/runtime.json" }
        try { $cfg = Read-IG5Text $configPath | ConvertFrom-Json }
        catch { throw "引擎清单 JSON 无效: $engine/runtime.json" }
        $engineRoot = Join-Path $base $engine
        $requiredFields = if ($engine -eq 'ghidra') { @('pythonExe', 'ghidraHome', 'javaHome') } else { @('pythonExe', 'headlessExe', 'headless32Exe', 'x64dbgExe', 'x32dbgExe') }
        foreach ($key in $requiredFields) {
            if (-not $cfg.$key) { throw "引擎清单缺少字段: $engine/$key" }
            $component = Resolve-IG5PackPath $engineRoot ([string]$cfg.$key)
            if (-not (Test-IG5Path $component)) { throw "缺少运行组件: $engine/$($cfg.$key)" }
        }
        $python = Split-Path (Resolve-IG5PackPath $engineRoot ([string]$cfg.pythonExe)) -Parent
        $required = @((Join-Path $python 'python312.zip'), (Join-Path $python 'python312.dll'), (Join-Path $python 'python312._pth'), (Join-Path $python 'LICENSE.txt'))
        if ($engine -eq 'ghidra') {
            $ghidra = Resolve-IG5PackPath $engineRoot ([string]$cfg.ghidraHome)
            $java = Resolve-IG5PackPath $engineRoot ([string]$cfg.javaHome)
            $required += @((Join-Path $ghidra 'Ghidra\Framework\Utility\lib\Utility.jar'), (Join-Path $ghidra 'LICENSE'), (Join-Path $ghidra 'bom.json'),
                (Join-Path $ghidra 'licenses'), (Join-Path $java 'bin\java.exe'), (Join-Path $java 'bin\server\jvm.dll'), (Join-Path $java 'legal'),
                (Join-Path $python 'pylib\pyghidra\__init__.py'), (Join-Path $python 'pylib\jpype\__init__.py'), (Join-Path $python 'pylib\packaging\__init__.py'),
                (Join-Path $python 'pylib\_jpype.cp312-win_amd64.pyd'), (Join-Path $python 'pylib\org.jpype.jar'))
            foreach ($pattern in @('pyghidra-*.dist-info', 'jpype1-*.dist-info', 'packaging-*.dist-info')) {
                $pylibPath = Join-Path $python 'pylib'
                $matches = if (Test-IG5Path $pylibPath Container) { @((New-Object IO.DirectoryInfo (ConvertTo-IG5IOPath $pylibPath)).GetDirectories($pattern)) } else { @() }
                if (@($matches).Count -ne 1 -or -not (Test-IG5Path ((Get-IG5FullPath $matches[0].FullName) + '\METADATA') Leaf)) { throw "缺少或重复 Python 依赖许可证元数据: ghidra/python/pylib/$pattern" }
            }
        } else {
            if ($cfg.bridge -ne 'ig5-native' -or $cfg.mode -ne 'headless') { throw '默认 x64dbg 发行包必须为 ig5-native/headless' }
            foreach ($bits in @('32', '64')) {
                $exe = if ($bits -eq '64') { $cfg.headlessExe } else { $cfg.headless32Exe }
                $debug = Split-Path (Resolve-IG5PackPath $engineRoot ([string]$exe)) -Parent
                foreach ($name in @("plugins\ig5-bridge.dp$bits", "x${bits}_bridge.dll", "x${bits}_dbg.dll", 'TitanEngine.dll', 'jansson.dll', 'msvcp140.dll', 'vcruntime140.dll')) { $required += Join-Path $debug $name }
                if (Test-IG5Path (Join-Path $debug "plugins\x64dbg-automate.dp$bits")) { throw "存在不兼容调试插件: x64dbg-automate.dp$bits" }
            }
            foreach ($name in @('NOTICE.txt', 'x64dbg-LICENSE.txt', 'Python-LICENSE.txt', 'Jansson-LICENSE.txt', 'TitanEngine-LICENSE.txt', 'license-sources.json', 'Qt-GPL-3.0.txt', 'Qt-LGPL-3.0.txt')) { $required += Join-Path $engineRoot "licenses\$name" }
        }
        foreach ($component in $required) {
            if (-not (Test-IG5Path $component)) { throw "缺少运行组件或许可证: $(Get-IG5RelativePath $base $component)" }
            if (Test-IG5Path $component Container) {
                if (-not @(Get-IG5PackFiles $component).Count) { throw "运行组件/许可证目录为空: $(Get-IG5RelativePath $base $component)" }
            }
        }
    }
    $extensions = Assert-IG5RuntimeExtensions $base
    $actual = @(Get-IG5PackFiles $base | Where-Object { -not $extensions.ContainsKey((Get-IG5RelativePath $base $_.FullName)) })
    $runtimeChecked = 0
    foreach ($file in $actual) {
        $relative = Get-IG5RelativePath $base $file.FullName
        if ($relative -eq 'manifest.json') { continue }
        if (-not $records.ContainsKey($relative)) { throw "运行包含未登记文件: $relative" }
        $hash = Get-IG5Hash $file.FullName
        if (-not $hash.Equals([string]$records[$relative].sha256, [StringComparison]::OrdinalIgnoreCase)) { throw "运行包 SHA-256 不符: $relative" }
        $runtimeChecked++
        if ($runtimeProgress -and $runtimeChecked % 4096 -eq 0) { Write-Host "[VERIFY] runtime SHA-256: $runtimeChecked / $($records.Count)" }
    }
    if (($actual.Count - $(if (Test-IG5Path (Join-Path $base 'manifest.json')) { 1 } else { 0 })) -ne $records.Count) { throw '运行包清单与实际文件数量不符' }
    if ($runtimeProgress) { Write-Host "[OK] runtime SHA-256: $runtimeChecked files verified" }
    return [pscustomobject]@{ Root = $base; Manifest = $manifest; ManifestPath = $manifestPath; Records = $records; Legacy = [bool]$prefix; Files = $records.Count }
}

function Copy-IG5Pack {
    param(
        [Parameter(Mandatory)][string]$From,
        [Parameter(Mandatory)][string]$To,
        [string[]]$ExtraExclude = @(),
        [switch]$PortableRelease,
        [string[]]$SampleSpecificFiles = @()
    )
    [IO.Directory]::CreateDirectory((ConvertTo-IG5IOPath $To)) | Out-Null
    foreach ($file in Get-IG5PackFiles $From -PortableRelease:$PortableRelease -SampleSpecificFiles $SampleSpecificFiles -ExtraExclude $ExtraExclude) {
        $relative = Get-IG5RelativePath $From $file.FullName
        $destination = Resolve-IG5PackPath $To $relative
        [IO.Directory]::CreateDirectory((ConvertTo-IG5IOPath (Split-Path $destination -Parent))) | Out-Null
        [IO.File]::Copy((ConvertTo-IG5IOPath $file.FullName), (ConvertTo-IG5IOPath $destination), $true)
    }
}

function Test-IG5RuntimeVersion {
    param([string]$AssetVersion, [string]$PluginVersion)
    # 1.1/1.2/1.3 reuse the exact sealed 1.0.0 native engines; 1.4.0+ ships its own
    # verified headless-slim runtime manifest matching exact pluginVersion.
    # Keep the original 1.0.0 manifests and SHA-256 pins byte-for-byte intact.
    return ($AssetVersion -ceq $PluginVersion -or ($PluginVersion -cin @('1.1.0','1.2.0','1.3.0') -and $AssetVersion -ceq '1.0.0'))
}

function Write-IG5RuntimeManifest {
    param([Parameter(Mandatory)]$Validated, [Parameter(Mandatory)][string]$Destination, [string]$PluginVersion)
    if (-not $Validated.Legacy) { [IO.File]::Copy((ConvertTo-IG5IOPath $Validated.ManifestPath), (ConvertTo-IG5IOPath (Join-Path $Destination 'manifest.json')), $true); return }
    $files = @($Validated.Records.Keys | Sort-Object | ForEach-Object { $r = $Validated.Records[$_]; @{path=$_;bytes=[long]$r.bytes;sha256=[string]$r.sha256} })
    $manifest = @{schemaVersion=1;pluginVersion=$PluginVersion;platform='win32-x64';engines=@('ghidra','x64dbg');files=$files}
    [IO.File]::WriteAllText((ConvertTo-IG5IOPath (Join-Path $Destination 'manifest.json')), ($manifest | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
}

function Assert-IG5FileInventory {
    param([string]$Root, [object[]]$Files, [string]$Label, [switch]$IncludeExcluded, [string[]]$IgnoredPrefixes = @(), [switch]$IncludeUnlistedRootFiles)
    if (-not $Files.Count) { throw "文件清单为空: $Label" }
    $progress = $Files.Count -ge 4096
    $progressLabel = [regex]::Replace([string]$Label, '[^A-Za-z0-9._/-]', '_')
    if ($progressLabel.Length -gt 80) { $progressLabel = $progressLabel.Substring(0,80) }
    if ($progress) { Write-Host "[VERIFY] ${progressLabel}: $($Files.Count) inventory entries; checking sizes/paths..." }
    $registered = 0
    $records = @{}
    foreach ($record in $Files) {
        $relative = ([string]$record.path).Replace('\', '/')
        $full = Resolve-IG5PackPath $Root $relative
        if ($records.ContainsKey($relative) -or [string]$record.sha256 -notmatch '^[a-fA-F0-9]{64}$' -or [long]$record.bytes -lt 0) { throw "无效文件清单: $Label/$relative" }
        if (-not (Test-IG5Path $full Leaf)) { throw "安装源缺少文件: $Label/$relative" }
        $actualBytes = (New-Object IO.FileInfo (ConvertTo-IG5IOPath $full)).Length
        if ($actualBytes -ne [long]$record.bytes) { throw "安装源文件长度不符: $Label/$relative`nExpected bytes: $($record.bytes); actual bytes: $actualBytes. Source files were not changed." }
        $records[$relative] = $record
        $registered++
        if ($progress -and $registered % 4096 -eq 0) { Write-Host "[VERIFY] $progressLabel sizes/paths: $registered / $($Files.Count)" }
    }
    $actual = @(Get-IG5PackFiles $Root -IncludeExcluded:$IncludeExcluded -IncludeUnlistedRootFiles:$IncludeUnlistedRootFiles | Where-Object {
        $candidate = Get-IG5RelativePath $Root $_.FullName
        $ignored = $false
        foreach ($prefix in $IgnoredPrefixes) { if ($candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { $ignored = $true; break } }
        -not $ignored
    })
    $checked = 0
    foreach ($file in $actual) {
        $relative = Get-IG5RelativePath $Root $file.FullName
        if (-not $records.ContainsKey($relative)) { throw "安装源含未登记文件: $Label/$relative" }
        $actualHash = Get-IG5Hash $file.FullName
        if ($actualHash -ne [string]$records[$relative].sha256) {
            throw "安装源 SHA-256 不符: $Label/$relative`nExpected SHA-256: $($records[$relative].sha256)`nActual SHA-256: $actualHash`nBytes: $($file.Length). Do not edit the manifest or skip validation. For immutable asset repair use install.ps1 -RepairAssets with the pinned original ZIP via -DistributionArchive, or verified -DistributionRoot. Existing DSH installation is unchanged."
        }
        $checked++
        if ($progress -and $checked % 4096 -eq 0) { Write-Host "[VERIFY] $progressLabel SHA-256: $checked / $($Files.Count)" }
    }
    if ($actual.Count -ne $records.Count) { throw "安装源清单数量不符: $Label" }
    if ($progress) { Write-Host "[OK] $progressLabel SHA-256: $checked files verified" }
}

function Get-IG5CoreInventory {
    param([string]$Root)
    # Freeze plugin code before any potentially long asset preparation. Assets
    # are validated independently against their immutable distribution pins.
    foreach ($file in Get-IG5PackFiles $Root) {
        $relative = Get-IG5RelativePath $Root $file.FullName
        if ($relative.StartsWith('runtimes/', [StringComparison]::OrdinalIgnoreCase) -or $relative.StartsWith('third_party/sources/', [StringComparison]::OrdinalIgnoreCase)) { continue }
        @{path=$relative;bytes=$file.Length;sha256=(Get-IG5Hash $file.FullName)}
    }
}

function Assert-IG5ReleaseCore {
    param([string]$Root, [string]$PluginVersion)
    $parentManifest = Join-Path (Split-Path $Root -Parent) 'manifest.json'
    if (-not (Test-IG5Path $parentManifest Leaf)) { throw 'Asset repair of a full/partial package requires its complete outer manifest.json; use a fresh Source ZIP instead.' }
    $release = Read-IG5Text $parentManifest | ConvertFrom-Json
    if ($release.schemaVersion -ne 1 -or $release.platform -ne 'win32-x64' -or -not $release.files -or [string]$release.pluginVersion -cne $PluginVersion) { throw 'Asset repair release inventory identity/version is invalid' }
    $prefix = (Split-Path $Root -Leaf) + '/'
    $ignored = @('runtimes/', 'third_party/sources/')
    $files = @($release.files | Where-Object { ([string]$_.path).StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) } | ForEach-Object {
        $relative = ([string]$_.path).Substring($prefix.Length).Replace('\','/')
        $null = Resolve-IG5PackPath $Root $relative
        if (-not $relative.StartsWith('runtimes/', [StringComparison]::OrdinalIgnoreCase) -and -not $relative.StartsWith('third_party/sources/', [StringComparison]::OrdinalIgnoreCase)) {
            @{path=$relative;bytes=$_.bytes;sha256=$_.sha256}
        }
    })
    Assert-IG5FileInventory $Root $files 'plugin-core' -IgnoredPrefixes $ignored
    # Keep the authenticated outer-manifest records, rather than re-snapshotting
    # possibly changed code after a download or donor copy.
    return $files
}

function Assert-IG5PluginSource {
    param([string]$Root, [switch]$CoreOnly)
    Assert-IG5NoReparsePath $Root
    if (-not (Test-IG5Path $Root Container) -or ([IO.File]::GetAttributes((ConvertTo-IG5IOPath $Root)) -band [IO.FileAttributes]::ReparsePoint)) { throw 'Plugin source must be a real directory' }
    # Keep this list aligned with the modules loaded by index.js, workers and the profile entry points.
    $required = @('package.json','index.js','client.js','engine_runtime.js','advanced_tools.js','integration_tools.js','analysis_tools.js','workflow.js',
        'semantic_diff.js','semantic_diff_async.js','semantic_diff_worker.js','source/project_store.js','source/attachment_lease.js','source/address_ref.js','source/host_platform.js','source/worker_transport.js',
        'source/audit_history.js','source/patch_export.js','source/history_index.js','source/json_output.js','source/reverse_runtime.js','source/kernel_jobs.js',
        'source/function_dossier.js','source/investigation_store.js','source/investigation_workflow.js','source/knowledge_catalog.js','source/knowledge_seeds.js','source/knowledge_documents.js','source/knowledge_io.js',
        'source/research_v2_contract.js','source/research_v2_store.js','source/knowledge_v2.js','source/knowledge_v2_compat.js','source/knowledge_publish_v2.js','source/research_case_index.js','source/research_case_bridge.js','source/method_registry.js','source/method_applicability.js','source/experiment_shadow.js','source/bitvector_contract.js','source/bitvector_replay.js','source/bitvector_solver.js','source/candidate_workflow.js','source/bitvector_provider.js','source/bitvector_provider_adapter.js','source/cff_overlay.js','source/cff_workflow.js','source/cff_state.js','source/cff_state_workflow.js','source/vm_instances.js','source/vm_instance_workflow.js','source/research_discovery.js','source/research_discovery_review.js','scripts/discover_research_sources.mjs','scripts/review_research_discovery.mjs','worker/bitvector_verify.py','scripts/publish_research_v2.mjs',
        'source/analysis_artifacts.js','source/analysis_jobs.js','source/analysis_worker.js','source/apk_zip.js','source/apk_der.js','source/apk_axml.js','source/apk_dex.js','source/apk_rules.js','source/apk_manifest.js','source/apk_analysis.js','source/crypto_analysis.js','source/crypto_recovery.js','source/protocol_analysis.js','source/protocol_inference.js',
        'worker/ig5_worker.py','worker/scan_analysis.py','worker/behavior_rules.py','worker/behavior_inventory.py','worker/string_decoding.py','worker/packer_rules.py','worker/packer_analysis.py','worker/firmware_rules.py','worker/firmware_io.py','worker/firmware_fs.py','worker/firmware_images.py','worker/firmware_scan.py','worker/firmware_cli.py','source/firmware_jobs.js','worker/advanced_analysis.py','worker/execution_analysis.py','worker/memory_image.py','worker/cpu_emulator.py','worker/vendor/NOTICE.txt',
        'worker/ig5_kernel.py','worker/kernel_image.py','worker/kernel_analysis.py','worker/kernel_rtti.py','worker/kernel_decompile.py',
        'worker/vendor/unicorn/__init__.py','worker/vendor/unicorn/lib/unicorn.dll',
        'adapters/ghidra/worker.py','adapters/ghidra/decode_scan.py','adapters/ghidra/pcode_view.py','adapters/ghidra/switch_analysis.py','adapters/ghidra/microcode_analysis.py','adapters/ghidra/script_api.py','adapters/ghidra/jpype-patch/JPypeContext.java','adapters/ghidra/jpype-patch/upstream/org.jpype.jar',
        'adapters/kernel/native/ig5_decompiler.dll','adapters/kernel/native/build-proof.json','adapters/kernel/native/Ghidra-LICENSE.txt','adapters/kernel/native/NOTICE','adapters/kernel/native/zlib-README.txt',
        'adapters/ghidra/jpype-patch/LICENSE','adapters/ghidra/jpype-patch/UPSTREAM-NOTICE','adapters/ghidra/jpype-patch/NOTICE.txt','adapters/ghidra/jpype-patch/unicode-bootstrap.patch',
        'scripts/patch_ghidra_jpype.ps1','scripts/patch_ghidra_project_paths.ps1','adapters/ghidra/local-project-path/build_patch.py',
        'adapters/ghidra/local-project-path/local-project-path.patch','adapters/ghidra/local-project-path/NOTICE.txt','adapters/ghidra/local-project-path/README.md',
        'adapters/x64dbg/adapter.py','adapters/x64dbg/native/ig5-bridge.dp32','adapters/x64dbg/native/ig5-bridge.dp64','adapters/x64dbg/native/sha256.json',
        'scripts/runtime_pack.ps1','scripts/recover_legacy_project_lock.mjs','scripts/bootstrap_distribution.ps1','scripts/distribution.json','install.ps1','uninstall.ps1','cordis.patch.yml','README.md','HARNESS_PLUGIN.md','LICENSE','THIRD_PARTY_NOTICES.txt')
    $sourcePackage = Read-IG5Text (Join-Path $Root 'package.json') | ConvertFrom-Json
    $pkgVer = [string]$sourcePackage.version
    if ($pkgVer -cin @('1.1.0','1.2.0','1.3.0') -or (Test-IG5VersionAtLeast $pkgVer '1.4.0')) { $required += @('capture_tools.js','source/capture_service.js','source/capture_proxy.js','source/capture_ca.js','source/capture_review.js','source/capture_payload.js','source/delivered_payload.js','source/capture_state_trace.js','source/protocol_state.js','adapters/ghidra/deobfuscation_analysis.py','adapters/ghidra/deobfuscation_symbolic.py') }
    if ($pkgVer -cin @('1.1.0','1.2.0','1.3.0') -or (Test-IG5VersionAtLeast $pkgVer '1.4.0')) { $required += @('source/trace_jobs.js','worker/ig5_trace.py','worker/trace_analysis.py','worker/requirements-trace.txt','worker/trace_vendor/ig5-manifest.json','worker/trace_vendor/NOTICE.txt','worker/trace_vendor/triton.cp312-win_amd64.pyd','worker/trace_vendor/triton_library-1.0.0rc4.dist-info/RECORD','worker/trace_vendor/triton_library-1.0.0rc4.dist-info/LICENSE.txt','worker/trace_vendor/licenses/sources.json') }
    if ($pkgVer -cin @('1.2.0','1.3.0') -or (Test-IG5VersionAtLeast $pkgVer '1.4.0')) { $required += @('source/delegation_control.js','source/result_artifacts.js','source/function_batches.js','source/capability_catalog.js','source/json_output.js','adapters/ghidra/elf_addresses.py','adapters/ghidra/result_capture.py','docs/RELEASE_1.2.0.md') }
    if ($pkgVer -ceq '1.3.0' -or (Test-IG5VersionAtLeast $pkgVer '1.4.0')) { $required += @('docs/RELEASE_1.3.0.md','source/delegation_execution.js','source/investigation_root.js','source/investigation_assessment.js','source/investigation_verifier.js','source/autonomy_host.js','source/native_rea_bridge.js','source/native_js_static.js','source/native_android_bridge.js','source/analysis_trace_diff.js','source/delegation_messages.js','vendor/rea/rea.mjs','vendor/rea/LICENSE','vendor/rea/provenance.json') }
    if (Test-IG5VersionAtLeast $pkgVer '1.4.0') { $required += @('docs/RELEASE_1.4.0.md','scripts/build_slim_donor.ps1') }
    if (-not $CoreOnly) { $required += 'third_party/sources/manifest.json' }
    foreach ($skill in @('ig5-triage','ig5-deep-dive','ig5-patch-and-sign','ig5-diff','ig5-debug-live','ig5-crypto','ig5-protocol','ig5-reverse-agent')) { $required += "skills/$skill/SKILL.md" }
    foreach ($relative in $required) { if (-not (Test-IG5Path (Resolve-IG5PackPath $Root $relative) Leaf)) { throw "安装源缺少插件文件: $relative" } }
    # Enumerate before network or profile writes; reject links in the source code.
    $scanExclude = if ($CoreOnly) { @('runtimes', 'third_party/sources') } else { @() }
    foreach ($unused in Get-IG5PackFiles $Root -ExtraExclude $scanExclude) { }
    if ($CoreOnly) { return }
    $parentManifest = Join-Path (Split-Path $Root -Parent) 'manifest.json'
    if (Test-IG5Path $parentManifest Leaf) {
        try { $release = Read-IG5Text $parentManifest | ConvertFrom-Json }
        catch { throw "完整发行包清单 JSON 无效: $parentManifest" }
        if ($release.schemaVersion -ne 1 -or $release.platform -ne 'win32-x64' -or -not $release.files) { throw "完整发行包清单无效: $parentManifest" }
        $prefix = (Split-Path $Root -Leaf) + '/'
        $files = @($release.files | Where-Object { ([string]$_.path).StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) } | ForEach-Object {
            @{path=([string]$_.path).Substring($prefix.Length);bytes=$_.bytes;sha256=$_.sha256}
        })
        # A complete release must match its manifest, including unlisted root
        # artifacts. The source-pack allowlist must not hide injected files here.
        Assert-IG5FileInventory $Root $files 'plugin' -IncludeUnlistedRootFiles
    }
    Assert-IG5SourceAssets $Root $pkgVer
}

function Assert-IG5SourceAssets {
    param([string]$Root, [string]$PluginVersion = '')
    $sourcesRoot = Join-Path $Root 'third_party\sources'
    $manifestPath = Join-Path $sourcesRoot 'manifest.json'
    try { $sources = Read-IG5Text $manifestPath | ConvertFrom-Json }
    catch { throw '第三方源码清单 JSON 无效' }
    if ($sources.schemaVersion -ne 1 -or -not $sources.sources) { throw '第三方源码清单无效或为空' }
    if (-not $PluginVersion -and (Test-IG5Path (Join-Path $Root 'package.json') Leaf)) {
        try { $PluginVersion = [string](Read-IG5Text (Join-Path $Root 'package.json') | ConvertFrom-Json).version } catch {}
    }
    $companionPath = Join-Path $sourcesRoot 'companion-sources.json'
    $anySourceDirPresent = $false
    foreach ($source in $sources.sources) {
        $dirCheck = Resolve-IG5PackPath $sourcesRoot ([string]$source.directory)
        if (Test-IG5Path $dirCheck Container) { $anySourceDirPresent = $true; break }
    }
    if (-not $anySourceDirPresent -and (Test-IG5VersionAtLeast $PluginVersion '1.4.0') -and (Test-IG5Path $companionPath Leaf)) {
        try { $companion = Read-IG5Text $companionPath | ConvertFrom-Json }
        catch { throw '第三方伴随源码清单 JSON 无效' }
        if ($companion.schemaVersion -ne 1 -or [string]$companion.pluginVersion -cne $PluginVersion -or
            [string]$companion.archiveName -notmatch '^IG5-\d+\.\d+\.\d+-sources-compliance\.zip$' -or
            [long]$companion.archiveBytes -le 0 -or [string]$companion.archiveSha256 -notmatch '^[a-f0-9]{64}$' -or
            [string]$companion.sourceManifestSha256 -cne (Get-IG5Hash $manifestPath)) {
            throw '第三方伴随源码清单元数据或主清单 SHA-256 校验失败'
        }
        foreach ($notice in @('THIRD_PARTY_NOTICES.txt', 'LICENSE')) {
            if (-not (Test-IG5Path (Resolve-IG5PackPath $Root $notice) Leaf)) { throw "伴随源码模式缺少必需合规声明文件: $notice" }
        }
        $allowedFiles = @{ 'manifest.json' = $true; 'companion-sources.json' = $true }
        $seenInv = @{}
        foreach ($source in $sources.sources) {
            $invRel = ([string]$source.fileInventory).Replace('\', '/')
            $inventoryPath = Resolve-IG5PackPath $sourcesRoot $invRel
            if ($seenInv.ContainsKey($invRel)) { throw "第三方源码清单重复: $invRel" }
            $seenInv[$invRel] = $true
            if (-not (Test-IG5Path $inventoryPath Leaf)) { throw "缺少第三方源码逐文件清单: $invRel" }
            $expectedHash = [string]$companion.provenanceSha256.$invRel
            if ($expectedHash -notmatch '^[a-f0-9]{64}$' -or (Get-IG5Hash $inventoryPath) -cne $expectedHash) {
                throw "伴随源码溯源清单 SHA-256 不符: $invRel"
            }
            $inventoryText = Read-IG5Text $inventoryPath
            $inventory = $inventoryText | ConvertFrom-Json
            $rawRows = $inventoryText.TrimStart().StartsWith('[')
            $inventoryRows = if ($rawRows) { @($inventory) } else { @($inventory.files) }
            if (@($inventoryRows).Count -ne [long]$source.fileCount -or (-not $rawRows -and [long]$inventory.fileCount -ne [long]$source.fileCount)) {
                throw "第三方源码数量不符: $($source.directory)"
            }
            $allowedFiles[$invRel] = $true
        }
        foreach ($file in Get-IG5PackFiles $sourcesRoot) {
            $rel = Get-IG5RelativePath $sourcesRoot $file.FullName
            if (-not $allowedFiles.ContainsKey($rel)) { throw "伴随源码目录含未登记文件: third_party/sources/$rel" }
        }
        return
    }
    $seen = @{}
    foreach ($source in $sources.sources) {
        $directory = Resolve-IG5PackPath $sourcesRoot ([string]$source.directory)
        $inventoryPath = Resolve-IG5PackPath $sourcesRoot ([string]$source.fileInventory)
        if ($seen.ContainsKey($directory)) { throw "第三方源码目录重复: $($source.directory)" }
        $seen[$directory] = $true
        if (-not (Test-IG5Path $inventoryPath Leaf)) { throw "缺少第三方源码逐文件清单: $($source.fileInventory)" }
        $inventoryText = Read-IG5Text $inventoryPath
        $inventory = $inventoryText | ConvertFrom-Json
        # Fixed source acquisition emits raw row arrays; older archives use a
        # { fileCount, files } envelope. Preserve both without member-enumerating
        # an array's missing fileCount into thousands of null values.
        $rawRows = $inventoryText.TrimStart().StartsWith('[')
        $inventoryRows = if ($rawRows) { @($inventory) } else { @($inventory.files) }
        if (@($inventoryRows).Count -ne [long]$source.fileCount -or (-not $rawRows -and [long]$inventory.fileCount -ne [long]$source.fileCount)) { throw "第三方源码数量不符: $($source.directory)" }
        Assert-IG5FileInventory $directory @($inventoryRows) ([string]$source.directory)
    }
}
